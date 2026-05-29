import { Card, Typography } from 'antd';

const { Title, Paragraph } = Typography;

export default function Dashboard() {
  return (
    <Card>
      <Title level={3}>控制台首页(待开发)</Title>
      <Paragraph>SASE 平台运维总览 — 各项指标/PoP 状态/告警等待后续刀。</Paragraph>
    </Card>
  );
}
