param(
    [string]$Text = "Welcome to AegisGraph. An autonomous incident remediation agent powered by FalkorDB.",
    [string]$OutputFile = "test_audio.wav"
)

Add-Type -AssemblyName System.Speech
$synth = New-Object System.Speech.Synthesis.SpeechSynthesizer
try {
    $synth.SelectVoice("Microsoft Zira Desktop")
} catch {
    # Fallback to default voice
}
$synth.Rate = 0
$synth.SetOutputToWaveFile($OutputFile)
$synth.Speak($Text)
$synth.Dispose()
Write-Host "Generated: $OutputFile"
