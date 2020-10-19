rule rule_agtesla : Trojan
{
    meta:
        description = "Agent Tesla PE32 analysis found @ dasmalwerk"
        author = "Thais Marques"
        date = "2020-10-19"
        reference = "https://dasmalwerk.eu/"
        anyrun_reference = "https://any.run/malware-trends/agenttesla"
        hash1 = "d3653291005f22c50e3ca31f6dfa9fcb28fd828290736ee57d775a8938aef9ee"
        hash2 = "4753a049547fa90686a21d981602b4675228b2f7f49e6c7e9dccf8b06469f950"
        hash3 = "676b02d81ccb54835e6c176ca797757e4e61cd3d6dab30e91bc55bbb65471dee"
    strings:

        $pub1="PublicKeyToken=b77a5c561934e089" nocase

        $file1="mii.exe" nocase
        $file2="figg.exe" nocase
        $file3="ygg.exe" nocase

    condition:
        ($pub1) and (1 of ($file*))
}