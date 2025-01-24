rule Suspicious_JS
{
    meta:
        description = "Detects JavaScript in PDFs"
        author = "Your Name"
        reference = "https://malwareanalysis.com"
        date = "2025-01-24"
    strings:
        $js1 = "/JavaScript"
        $js2 = "/JS"
    condition:
        any of them
}

rule Suspicious_OpenAction
{
    meta:
        description = "Detects OpenAction in PDFs, often used to execute scripts automatically"
        author = "Your Name"
        date = "2025-01-24"
    strings:
        $openaction = "/OpenAction"
    condition:
        $openaction
}

rule Embedded_File
{
    meta:
        description = "Detects embedded files in PDFs"
        author = "Your Name"
        date = "2025-01-24"
    strings:
        $embed1 = "/EmbeddedFile"
    condition:
        $embed1
}
