Copy-Item -LiteralPath "$PSScriptRoot\owlvex-manual-test.safe.js" -Destination "$PSScriptRoot\owlvex-manual-test.current.js" -Force
Write-Host "Loaded safer test file into owlvex-manual-test.current.js"
