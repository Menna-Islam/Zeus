rule Zeus_Malware_General
{
    meta:
        description = "Detect Zeus malware artifacts in binaries, config files, and memory dumps"
        author = "Your Name"
        date = "2024-12-18"

    strings:
        $zeus_str1 = "ZeuS"                             
        $zeus_config_keyword = "ZeusConfig"             
        $c2_traffic = "GET /update HTTP/1.1"            
        $c2_request = "POST /commands HTTP/1.1"         
        $user_agent = "Mozilla/5.0"                     
        $mz_header = { 4D 5A }                          
        $pe_header = { 50 45 00 00 }                    
        $nop_sled = { 90 90 90 90 }                    
        $shellcode_pattern = { 41 BA 80 00 00 00 48 B8 38 A1 }  

    condition:
        // Ensure $nop_sled is matched with other Zeus indicators
        ($nop_sled and any of ($zeus_str1, $zeus_config_keyword, $c2_traffic, $c2_request, $user_agent)) 
        or $mz_header or $pe_header or $shellcode_pattern
}
