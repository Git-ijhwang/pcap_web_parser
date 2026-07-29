import IeDecoder from '../common/IeDecoder';

function PfcpIeTable({ ies, level = 0 })
{
  const bgColor=[ "#BBC863", "#F0E491", "#00e0e0" ];

  return (
    <>
    {ies.map((ie, idx) => {
      const subIes = ie.ie_value?.SubIeList;
      const isGrouped = Array.isArray(subIes) && subIes.length > 0;
      const dataRows = Math.ceil(ie.ie_len / 4);
      let lenRowSpan = dataRows+1;
      let group = isGrouped ? level+1 : level ? level : 2;
      let sublen = 0;
      let remain = 0;
      let class_name = "even-git-ie";

      if (idx%2 > 0) {
        class_name = "odd-pfcp-ie"
      }

      let group_class = "";
      if (level ===0){
        group_class = "grouped_ie"
      }
      else {
        group_class = "sub_ies"
      }

      if (group === 1 && isGrouped) {
        subIes.forEach((sub) => {
          remain = (sub.ie_len % 4? 1: 0) + remain;
          sublen = Math.trunc((sub.ie_len+4) / 4) + sublen;
        })
        lenRowSpan = remain + sublen + 1;
      }

      return (
        <>
          <tr key={idx}>

            <th rowSpan={lenRowSpan}
              colSpan={Math.max(1,  group)}
              className={`vertical ${class_name} ${group_class}`}
            >
              <b> {ie.type_str} </b>
            </th>

            {group === 1 && level === 0 && (
              <th className={`vertical ${class_name} ${group_class}`} >
                {/* Sub Ies */}
              </th>
            )}

            {
            (
              <>
                <td colSpan="16" style={{ textAlign:"center"}}
                  className={`${level === 0 ? "ie_header":"sub_ies"} field`}>
                  Type: {ie.type_str} [{ie.ie_type}]
                </td>
                  
                <td colSpan="16" style={{ textAlign: "center" }} 
                  className={`${level === 0 ? "ie_header":"sub_ies"} field`}>
                  Length: {ie.ie_len}
                </td>
              </>
            )}

          </tr>

          {!isGrouped && (
            IeDecoder(ie.ie_value, ie.ie_type, lenRowSpan, ie.length )
          )}

          {isGrouped && (
            <PfcpIeTable ies={subIes} level={level + 1} />
          )}
        </>
      );

    })}
    </>
  );
}
export default PfcpIeTable;