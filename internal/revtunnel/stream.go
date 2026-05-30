package revtunnel

// stream.go 是 revtunnel 的原始 TCP 流多路复用层(Slice78 零暴露面出站,L2 §3.4.1)。
//
// 动机:HTTP RoundTrip(W1)只承载 HTTP 请求/响应帧;PoP 侧 ZTNA 终结器(ztnaterm)经内核 REDIRECT
// 透明代理终结任意 TCP 流后,需把这条流经已注册的 connector **反向**送进私网到达内部 app(私网零入站开口)。
// 故在同一条 connector↔PoP 长连上自写一个最小帧 mux:多条逻辑流(streamID 区分)共用一条物理连接。
//
// 帧格式(定长二进制头 + 变长 payload,binary.BigEndian):
//
//	+--------+------------+--------+----------------+
//	| Type   | StreamID   | Len    | Payload(Len)   |
//	| uint8  | uint32     | uint32 |                |
//	+--------+------------+--------+----------------+
//
//	Type:
//	  OPEN  PoP→connector:开一条新流,Payload = 原始目的 dst(host:port,供 connector net.Dial)。
//	  DATA  双向:流数据(Payload = 字节)。
//	  CLOSE 双向:流正常半关/全关(写端不再发 DATA;读端收 CLOSE 即 EOF)。
//	  RST   双向:流异常终止(dial 失败 / 读写错;读端收 RST 即 errStreamReset)。
//
// 方向约定(本刀第一刀定界):**仅 PoP 侧 OpenStream → connector 侧 dial**(OPEN 单向 PoP→connector)。
// connector 不主动开流(无 OPEN 出向);故 streamID 由 PoP 侧单调分配,无双向分配冲突。
//
// 诚实定界(§3.4.1 第一刀):仅 TCP;**无流控/背压**(每流一个有缓冲管道,满则阻塞读循环——
// 单条慢流会拖住整条 mux 的所有流,后续需背压再换 yamux);CLOSE 为半关语义但本刀代理用 io.Copy 双向,
// 任一端 EOF 即收尾。
import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// 帧类型。
const (
	frameOpen  uint8 = 1
	frameData  uint8 = 2
	frameClose uint8 = 3
	frameRST   uint8 = 4
)

const (
	frameHeaderLen  = 9       // Type(1) + StreamID(4) + Len(4)
	maxFramePayload = 1 << 16 // 单帧 payload 上限(64 KiB;防恶意巨帧撑爆内存/读循环)
	streamReadBuf   = 64      // 每流入站管道缓冲帧数(无流控的兜底缓冲;满则读循环阻塞)
)

var (
	// errMuxClosed 表示底层 mux 连接已关闭(物理连接断开 / 被替换 / Registry 驱逐)。
	errMuxClosed = errors.New("revtunnel: mux 连接已关闭")
	// errStreamReset 表示对端发了 RST(异常终止,如 connector dial 失败)。
	errStreamReset = errors.New("revtunnel: 流被对端 RST")
	// errStreamClosed 表示本地流已 Close。
	errStreamClosed = errors.New("revtunnel: 流已关闭")
)

// muxConn 在一条物理连接(connector↔PoP)上承载多条逻辑流。
//
// 读循环(单 goroutine)解帧 → 按 streamID 分发到对应 stream 的入站管道;写经 writeMu 串行化整帧写
// (避免多流并发写交错损坏帧边界)。
type muxConn struct {
	conn net.Conn  // 写帧目标(物理连接)
	rd   io.Reader // 读帧源(默认 == conn;PoP 侧含 Hello JSON 解码器的读端缓冲,见 newMuxConnReader)

	writeMu sync.Mutex // 串行化整帧写(防并发交错)

	mu      sync.Mutex // 守 streams / nextID / closed
	streams map[uint32]*stream
	nextID  uint32 // PoP 侧分配新 streamID(server 侧用;connector 侧不分配)
	server  bool   // true=PoP 侧(可 openStream 主动开流);false=connector 侧(只被动响应 OPEN)
	closed  bool

	// onOpen 是 connector 侧处理 OPEN 帧的回调(由 ServeStream 设:dial + 双向泵)。PoP 侧为 nil。
	// 流条目已在 readLoop 内同步 acceptStream 建好,以(已就绪的)stream + dst 传入;回调内**必须 go 起**
	// dial+泵(勿阻塞读循环,否则后续帧停止分发)。
	onOpen func(s *stream, dst string)
}

// newMuxConn 在 conn 上构造 mux(读帧 == conn)。server=true 为 PoP 侧(主动 openStream);false 为 connector 侧。
func newMuxConn(conn net.Conn, server bool) *muxConn {
	return newMuxConnReader(conn, conn, server)
}

// newMuxConnReader 构造 mux,读帧从 rd(可含已缓冲字节),写帧到 conn。
// 用于 PoP 侧:Hello 经 json.Decoder 读时可能预读了首帧字节,须把 decoder.Buffered() 接在 conn 前
// (io.MultiReader),否则首帧字节丢失。connector 侧 rd==conn(裸 JSON Encode 无读端预读)。
func newMuxConnReader(conn net.Conn, rd io.Reader, server bool) *muxConn {
	return &muxConn{
		conn:    conn,
		rd:      rd,
		streams: map[uint32]*stream{},
		server:  server,
	}
}

// openStream 分配 streamID,发 OPEN(payload=dst),返回逻辑流(io.ReadWriteCloser)。仅 PoP 侧。
func (m *muxConn) openStream(dst string) (*stream, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, errMuxClosed
	}
	m.nextID++
	id := m.nextID
	s := newStream(m, id)
	m.streams[id] = s
	m.mu.Unlock()

	if err := m.writeFrame(frameOpen, id, []byte(dst)); err != nil {
		m.removeStream(id)
		return nil, err
	}
	return s, nil
}

// writeFrame 串行写一整帧(头 + payload)。payload 可为 nil/空(CLOSE/RST)。
func (m *muxConn) writeFrame(typ uint8, id uint32, payload []byte) error {
	if len(payload) > maxFramePayload {
		return fmt.Errorf("revtunnel: 帧 payload 过大 %d > %d", len(payload), maxFramePayload)
	}
	var hdr [frameHeaderLen]byte
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:5], id)
	binary.BigEndian.PutUint32(hdr[5:9], uint32(len(payload)))
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	if _, err := m.conn.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := m.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// readLoop 单 goroutine 解帧分发,阻塞到连接断开/出错。退出时关闭所有流(EOF 唤醒读写端)。
// onOpen 处理 OPEN 帧(connector 侧 = dial + 双向泵;PoP 侧不应收到 OPEN)。
func (m *muxConn) readLoop() {
	defer m.closeAll(errMuxClosed)
	hdr := make([]byte, frameHeaderLen)
	for {
		if _, err := io.ReadFull(m.rd, hdr); err != nil {
			return
		}
		typ := hdr[0]
		id := binary.BigEndian.Uint32(hdr[1:5])
		ln := binary.BigEndian.Uint32(hdr[5:9])
		if ln > maxFramePayload {
			return // 恶意/损坏巨帧:终止整条 mux(数据面坏输入降级,不 panic)
		}
		var payload []byte
		if ln > 0 {
			payload = make([]byte, ln)
			if _, err := io.ReadFull(m.rd, payload); err != nil {
				return
			}
		}
		m.dispatch(typ, id, payload)
	}
}

// dispatch 按帧类型分发(读循环内调,单 goroutine)。
func (m *muxConn) dispatch(typ uint8, id uint32, payload []byte) {
	switch typ {
	case frameOpen:
		// 仅 connector 侧应收 OPEN。PoP 侧收到 OPEN 是协议违例(本刀 connector 不主动开流)→ 忽略。
		if m.server || m.onOpen == nil {
			return
		}
		// **同步** acceptStream(在 readLoop 内,先于处理下一帧):否则若 acceptStream 推迟到 onOpen 的
		// goroutine,紧随 OPEN 的 DATA 帧会因 lookup(id)==nil 被丢弃(竞态丢数据)。建好流条目再异步 dial+泵。
		s := m.acceptStream(id)
		if s == nil {
			return // mux 已关
		}
		m.onOpen(s, string(payload))
	case frameData:
		if s := m.lookup(id); s != nil {
			s.deliver(payload)
		}
	case frameClose:
		if s := m.lookup(id); s != nil {
			s.remoteClose()
		}
	case frameRST:
		if s := m.lookup(id); s != nil {
			s.remoteReset()
		}
	default:
		// 未知帧类型:忽略(向前兼容;不终止 mux)。
	}
}

func (m *muxConn) lookup(id uint32) *stream {
	m.mu.Lock()
	s := m.streams[id]
	m.mu.Unlock()
	return s
}

// acceptStream 在 connector 侧为收到的 OPEN 建一个流条目(connector 用它收 DATA、回 DATA/CLOSE/RST)。
func (m *muxConn) acceptStream(id uint32) *stream {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	s := newStream(m, id)
	m.streams[id] = s
	m.mu.Unlock()
	return s
}

func (m *muxConn) removeStream(id uint32) {
	m.mu.Lock()
	delete(m.streams, id)
	m.mu.Unlock()
}

// closeAll 关闭所有流(以 cause 唤醒阻塞的读写),并标记 mux 关闭。幂等。
func (m *muxConn) closeAll(cause error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	victims := make([]*stream, 0, len(m.streams))
	for _, s := range m.streams {
		victims = append(victims, s)
	}
	m.streams = map[uint32]*stream{}
	m.mu.Unlock()
	for _, s := range victims {
		s.shutdown(cause)
	}
	_ = m.conn.Close()
}

// Close 关闭 mux(关物理连接 + 所有流)。幂等。
func (m *muxConn) Close() error {
	m.closeAll(errMuxClosed)
	return nil
}

// ---- stream:一条逻辑流(io.ReadWriteCloser) ----

// stream 是 mux 上的一条逻辑流。Read 从入站管道读对端 DATA;Write 经 mux 发 DATA;Close 发 CLOSE。
type stream struct {
	mux *muxConn
	id  uint32

	inbound chan []byte // 入站 DATA 队列(读循环投递;Read 消费)

	mu        sync.Mutex
	readBuf   []byte // 上次 Read 未读完的剩余(部分读)
	remoteEOF bool   // 收到对端 CLOSE(读尽 inbound 后返 io.EOF)
	resetErr  error  // 收到 RST / mux 关闭(Read/Write 返此 err)
	localDone bool   // 本地已 Close(发过 CLOSE,不再发 DATA)

	closeOnce sync.Once
	doneCh    chan struct{} // 关闭(Close/RST/mux down)即 close,唤醒阻塞的 Read
}

func newStream(m *muxConn, id uint32) *stream {
	return &stream{
		mux:     m,
		id:      id,
		inbound: make(chan []byte, streamReadBuf),
		doneCh:  make(chan struct{}),
	}
}

// deliver 由读循环投递一帧 DATA(非阻塞地尽量入队;满则阻塞——本刀无流控,见文件头定界)。
func (s *stream) deliver(p []byte) {
	if len(p) == 0 {
		return
	}
	cp := append([]byte(nil), p...) // 拷贝(读循环复用 payload buf 已是新分配,但防御性拷贝保持所有权清晰)
	select {
	case s.inbound <- cp:
	case <-s.doneCh:
		// 流已关:丢弃(对端不会再读)。
	}
}

// remoteClose 标记对端半关(读尽 inbound 后 Read 返 EOF)。
func (s *stream) remoteClose() {
	s.mu.Lock()
	s.remoteEOF = true
	s.mu.Unlock()
	// 投递一个 nil 哨兵唤醒可能阻塞在空 inbound 的 Read(让其重新检查 remoteEOF)。
	select {
	case s.inbound <- nil:
	case <-s.doneCh:
	default:
	}
	s.reapIfDone()
}

// reapIfDone 在本地已 Close 且对端已 CLOSE 时从 mux 摘除流条目(防长连 mux 上短流累积泄漏)。
// 只摘除 map 条目、不强制 EOF(Read 经 remoteEOF 哨兵自然收尾);不置 resetErr。幂等(map delete 幂等)。
func (s *stream) reapIfDone() {
	s.mu.Lock()
	done := s.localDone && s.remoteEOF
	s.mu.Unlock()
	if done {
		s.mux.removeStream(s.id)
	}
}

// remoteReset 标记对端异常终止(Read/Write 立即返 errStreamReset)。
func (s *stream) remoteReset() {
	s.shutdown(errStreamReset)
}

// shutdown 以 cause 终止流(RST / mux down):置错并唤醒阻塞的 Read/Write。幂等。
func (s *stream) shutdown(cause error) {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		if s.resetErr == nil {
			s.resetErr = cause
		}
		s.mu.Unlock()
		close(s.doneCh)
		s.mux.removeStream(s.id)
	})
}

// Read 实现 io.Reader:从入站管道读对端 DATA。对端 CLOSE 且读尽 → io.EOF;RST/mux down → errStreamReset。
func (s *stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	if len(s.readBuf) > 0 {
		n := copy(p, s.readBuf)
		s.readBuf = s.readBuf[n:]
		s.mu.Unlock()
		return n, nil
	}
	if s.resetErr != nil {
		err := s.resetErr
		s.mu.Unlock()
		return 0, err
	}
	s.mu.Unlock()

	for {
		select {
		case <-s.doneCh:
			s.mu.Lock()
			err := s.resetErr
			s.mu.Unlock()
			if err == nil {
				err = io.EOF
			}
			return 0, err
		case chunk, ok := <-s.inbound:
			if !ok {
				return 0, io.EOF
			}
			if chunk == nil {
				// CLOSE 哨兵:若 inbound 已空且对端半关,返 EOF;否则继续等真实数据。
				s.mu.Lock()
				eof := s.remoteEOF && len(s.inbound) == 0
				s.mu.Unlock()
				if eof {
					return 0, io.EOF
				}
				continue
			}
			n := copy(p, chunk)
			if n < len(chunk) {
				s.mu.Lock()
				s.readBuf = chunk[n:]
				s.mu.Unlock()
			}
			return n, nil
		}
	}
}

// Write 实现 io.Writer:经 mux 发 DATA(分片到 maxFramePayload)。本地已 Close / RST / mux down → 报错。
func (s *stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	if s.resetErr != nil {
		err := s.resetErr
		s.mu.Unlock()
		return 0, err
	}
	if s.localDone {
		s.mu.Unlock()
		return 0, errStreamClosed
	}
	s.mu.Unlock()

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxFramePayload {
			chunk = chunk[:maxFramePayload]
		}
		if err := s.mux.writeFrame(frameData, s.id, chunk); err != nil {
			s.shutdown(errMuxClosed)
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Close 实现 io.Closer:发 CLOSE(本地半关,不再发 DATA),并从 mux 摘除。幂等。
func (s *stream) Close() error {
	s.mu.Lock()
	already := s.localDone
	s.localDone = true
	s.mu.Unlock()
	if !already {
		_ = s.mux.writeFrame(frameClose, s.id, nil) // best-effort:mux 已断也无妨
	}
	// 不立刻 close(doneCh):本地 Close 是半关,可能仍要读对端剩余 DATA(io.Copy 另一向)。
	// mux 断开 / 对端 RST / 对端 CLOSE 才真正终结读端。这里只摘除写端 + 双向都关时摘 map 条目。
	s.reapIfDone()
	return nil
}

// reset 发 RST(异常终止,如 connector dial 失败)并终结流。
func (s *stream) reset() {
	s.mu.Lock()
	done := s.resetErr != nil
	s.mu.Unlock()
	if !done {
		_ = s.mux.writeFrame(frameRST, s.id, nil)
	}
	s.shutdown(errStreamReset)
}
