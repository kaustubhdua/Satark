/*
  SATARK File Guard local starter rules
  License: CC0-1.0 for this original rule pack.
  These are review heuristics, not universal malware signatures or proof of safety.
  Rules inspect raw byte patterns only; SATARK does not extract document text.
*/

rule SATARK_Suspicious_PowerShell_Download_And_Execution
{
    meta:
        category = "script-behavior"
        severity = "review"
        confidence = "medium"
        false_positive_notes = "Legitimate administration and deployment scripts may download and execute code."
        source = "SATARK original heuristic"
    strings:
        $webclient = "System.Net.WebClient" ascii wide nocase
        $download = "DownloadString" ascii wide nocase
        $invoke = "Invoke-Expression" ascii wide nocase
    condition:
        filesize < 8MB and 2 of them
}

rule SATARK_PDF_AutoOpen_JavaScript
{
    meta:
        category = "document-active-content"
        severity = "review"
        confidence = "medium"
        false_positive_notes = "Some legitimate PDFs contain JavaScript actions; inspect provenance before deciding."
        source = "SATARK original heuristic"
    strings:
        $pdf = "%PDF-" ascii
        $open = "/OpenAction" ascii nocase
        $javascript = "/JavaScript" ascii nocase
        $js = "/JS" ascii nocase
    condition:
        filesize < 32MB and $pdf at 0 and $open and ($javascript or $js)
}

rule SATARK_OLE_Macro_AutoOpen_Shell
{
    meta:
        category = "document-active-content"
        severity = "review"
        confidence = "medium"
        false_positive_notes = "Legacy macro-enabled Office files can legitimately contain automation; this is not a malware verdict."
        source = "SATARK original heuristic"
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $auto = "AutoOpen" ascii wide nocase
        $shell = "Shell" ascii wide nocase
        $create = "CreateObject" ascii wide nocase
    condition:
        filesize < 16MB and $ole at 0 and 2 of ($auto, $shell, $create)
}

rule SATARK_JavaScript_Obfuscation_Cluster
{
    meta:
        category = "script-obfuscation"
        severity = "review"
        confidence = "low"
        false_positive_notes = "Bundlers, minifiers and legitimate obfuscated applications can contain these APIs."
        source = "SATARK original heuristic"
    strings:
        $eval = "eval(" ascii wide nocase
        $charcode = "fromCharCode" ascii wide nocase
        $unescape = "unescape(" ascii wide nocase
    condition:
        filesize < 8MB and 2 of them
}

rule SATARK_Dex_Dynamic_Loading_Cluster
{
    meta:
        category = "android-dynamic-loading"
        severity = "review"
        confidence = "low"
        false_positive_notes = "Legitimate plugin systems and packers may use dynamic class loading."
        source = "SATARK original heuristic"
    strings:
        $dex = "dex\n" ascii
        $loader = "DexClassLoader" ascii wide
        $load = "loadDex" ascii wide
    condition:
        filesize < 64MB and $dex at 0 and ($loader or $load)
}
