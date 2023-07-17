json = require("dkjson")

-- Các trường trong Traffic Syslog Palo Alto
traffic_fields={'domain','receive_time','serial_#','type','threat/content_type','config_version','generate_time','source_address','destination_address','nat_source_ip','nat_destination_ip','rule','source_user','destination_user','application','virtual_system','source_zone','destination_zone','inbound_interface','outbound_interface','log_action','time_logged','session_id','repeat_count','source_port','destination_port','nat_source_port','nat_destination_port','flags','ip_protocol','action','bytes','bytes_sent','bytes_received','packets','start_time','elapsed_time_(sec)','category','tpadding','sequence_number','action_flags','source_country','destination_country','cpadding','packets_sent','packets_received','session_end_reason','dg_hierarchy_level_1','dg_hierarchy_level_2','dg_hierarchy_level_3','dg_hierarchy_level_4','virtual_system_name','device_name','action_source','source_vm_uuid','destination_vm_uuid','tunnel_id/imsi','monitor_tag/imei','parent_session_id','parent_session_start_time','tunnel','sctp_association_id','sctp_chunks','sctp_chunks_sent','sctp_chunks_received','uuid_for_rule','http/2_connection','link_change_count','policy_id','link_switches','sdwan_cluster','sdwan_device_type','sdwan_cluster_type','sdwan_site','dynusergroup_name','xff_address','source_device_category','source_device_profile','source_device_model','source_device_vendor','source_device_os_family','source_device_os_version','source_hostname','source_mac_address','destination_device_category','destination_device_profile','destination_device_model','destination_device_vendor','destination_device_os_family','destination_device_os_version','destination_hostname','destination_mac_address','container_id','pod_namespace','pod_name','source_external_dynamic_list','destination_external_dynamic_list','host_id','serial_number','source_dynamic_address_group','destination_dynamic_address_group','session_owner','high_res_timestamp','nssai_sst','nssai_sd'}

-- Các trường trong Threat Syslog Palo Alto
threat_fields={'domain','receive_time','serial','type','threat/content_type','config_version','generate_time','source_address','destination_address','nat_source_ip','nat_destination_ip','rule','source_user','destination_user','application','virtual_system','source_zone','destination_zone','inbound_interface','outbound_interface','log_action','time_logged','session_id','repeat_count','source_port','destination_port','nat_source_port','nat_destination_port','flags','ip_protocol','action','url/filename','threat/content_name','category','severity','direction','sequence_number','action_flags','source_country','destination_country','cpadding','contenttype','pcap_id','filedigest','cloud','url_idx','user_agent','filetype','xff','referer','sender','subject','recipient','reportid','dg_hierarchy_level_1','dg_hierarchy_level_2','dg_hierarchy_level_3','dg_hierarchy_level_4','virtual_system_name','device_name','file_url','source_vm_uuid','destination_vm_uuid','http_method','tunnel_id/imsi','monitor_tag/imei','parent_session_id','parent_session_start_time','tunnel','thr_category','contentver','sig_flags','sctp_association_id','payload_protocol_id','http_headers','url_category_list','uuid_for_rule','http/2_connection','dynusergroup_name','xff_address','source_device_category','source_device_profile','source_device_model','source_device_vendor','source_device_os_family','source_device_os_version','source_hostname','source_mac_address','destination_device_category','destination_device_profile','destination_device_model','destination_device_vendor','destination_device_os_family','destination_device_os_version','destination_hostname','destination_mac_address','container_id','pod_namespace','pod_name','source_external_dynamic_list','destination_external_dynamic_list','host_id','serial_number','domain_edl','source_dynamic_address_group','destination_dynamic_address_group','partial_hash','high_res_timestamp','reason','justification','nssai_sst'}

-- Hàm tách các chữ trong chuỗi phân cách bởi "separator", nếu giữa các sub string là cặp dấu " " 
-- thì không phân tách các string được ngăn các bởi "separator" ví dụ: s = "a,b,"c,d",e"
-- thì ta có các sub string như sau: 'a', 'b', 'c,d' và 'e'
function split(inputString, separator)
    results = {}
    local inQuotes = false
    local substring = ""
    
    for i = 1, #inputString do
        local char = inputString:sub(i, i)
        
        if char == '"' then
            inQuotes = not inQuotes
        elseif char == separator and not inQuotes then
            table.insert(results, tostring(substring))
            substring = ""
        else
            substring = substring .. char
        end
    end
    
    table.insert(results, tostring(substring))
    return results
end

-- Hàm chính, dùng để Parser Syslog Palo Alto Input
function change_tag(tag, timestamp, record)
  log=record["log"]  
  log_table = {}     -- Chứa giá trị của các trường syslog
  record_new = {}      -- Record sau parser
  -- Parser Traffic Syslog
  if string.find(log,'TRAFFIC') then
    log_table = split(log,",")
    for i, value in ipairs(log_table) do
      if value == "" then
        log_table[i] = "null"
      end
    end
    for i,j in pairs(traffic_fields) do
      array_temp={}
      array_temp[j]=log_table[i]
      record_new[tostring(i)]=array_temp
    end
    return 2,timestamp, record_new
  -- Parser Threat Syslog
  elseif string.find(log,'THREAT') then
    log_table = split(log,",")
    for i, value in ipairs(log_table) do
      if value == "" then
        log_table[i] = "null"
      end
    end
    for i,j in pairs(threat_fields) do
      array_temp={}
      array_temp[j]=log_table[i]
      record_new[tostring(i)]=array_temp
    end
    return 2,timestamp, record_new
  else
    return tag,timestamp,record
  end
end
