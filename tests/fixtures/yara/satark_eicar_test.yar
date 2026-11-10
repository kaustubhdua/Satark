rule SATARK_EICAR_TEST_ONLY : test_fixture
{
    meta:
        author = "SATARK"
        description = "EICAR anti-malware test string; benign test fixture only"
        license = "CC0-1.0"
        not_a_malware_sample = true
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
