rule RansomNote
{
    meta:
        description = "Detects ransom note content by phrase patterns"
        severity = "critical"

    strings:
        $phrase1 = "your files have been encrypted" nocase
        $phrase2 = "send btc" nocase
        $phrase3 = "bitcoin wallet" nocase
        $phrase4 = "payment is required" nocase
        $phrase5 = "decrypt your files" nocase
        $phrase6 = "recover your files" nocase
        $phrase7 = "victim id" nocase

        $keyword1 = "ransom" nocase
        $keyword2 = "decrypt" nocase
        $keyword3 = "bitcoin" nocase
        $keyword4 = "wallet" nocase
        $keyword5 = "encrypted" nocase
        $keyword6 = "payment" nocase
        $keyword7 = "deadline" nocase

        $btc_addr = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
        $onion = /[a-z2-7]{16,56}\.onion/ nocase

    condition:
        any of ($phrase*) or
        3 of ($keyword*) or
        ($btc_addr and 2 of ($keyword*)) or
        ($onion and 2 of ($keyword*))
}
