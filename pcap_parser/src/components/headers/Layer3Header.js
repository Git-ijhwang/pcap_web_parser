import IpHeader from "./IpHeader";
// import Ip6Header from "./Ip6Header";

export default function Layer3Header({ l3, idx }) {
  if (l3.IP) return <IpHeader ip={l3.IP} depth={idx} />;
//   if (l3.IP6) return <Ip6Header ip6={l3.IP6} />;

return null;
}