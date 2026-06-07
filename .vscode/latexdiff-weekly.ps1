# latexdiff-weekly.ps1
# Called by LaTeX Workshop after a successful build.
# If the current file is a progress report ("Progress Report N.tex"),
# generates a latexdiff PDF against the previous progress report.

param(
    [string]$DocPath,   # %DOC% -- full path without extension
    [string]$OutDir     # %OUTDIR% -- build output directory
)

$filename = [System.IO.Path]::GetFileNameWithoutExtension($DocPath)
$dir      = [System.IO.Path]::GetDirectoryName($DocPath)

if ($filename -notmatch '^Progress Report\s+(\d+)$') {
    Write-Host "[latexdiff] Not a progress report -- skipping."
    exit 0
}

$pr     = [int]$Matches[1]
$prevPr = $pr - 1

if ($prevPr -lt 1) {
    Write-Host "[latexdiff] Progress Report 1 has no previous report to diff against -- skipping."
    exit 0
}

$prevFile = Join-Path $dir "Progress Report $prevPr.tex"
if (-not (Test-Path -LiteralPath $prevFile)) {
    Write-Host "[latexdiff] Previous progress report file not found in $dir -- skipping."
    exit 0
}

$currentFile  = "$DocPath.tex"
$diffBaseName = "diff_PR${prevPr}_PR${pr}"
$diffTex      = Join-Path $OutDir "$diffBaseName.tex"
$diffsDir     = Join-Path $dir "diffs"

if (-not (Test-Path -LiteralPath $diffsDir)) {
    New-Item -ItemType Directory -Path $diffsDir | Out-Null
}

Write-Host "[latexdiff] Progress Report $prevPr -> Progress Report $pr"
latexdiff $prevFile $currentFile | Out-File -FilePath $diffTex -Encoding utf8
if ($LASTEXITCODE -ne 0) {
    Write-Host "[latexdiff] ERROR: latexdiff failed"
    exit 1
}

Write-Host "[latexdiff] Compiling $diffBaseName.tex ..."
& latexmk -synctex=1 -interaction=nonstopmode -file-line-error -xelatex "-outdir=$OutDir" $diffTex
if ($LASTEXITCODE -ne 0) {
    Write-Host "[latexdiff] ERROR: xelatex compilation of diff failed"
    exit 1
}

$src = Join-Path $OutDir "$diffBaseName.pdf"
$dst = Join-Path $diffsDir "$diffBaseName.pdf"
if (Test-Path -LiteralPath $src) {
    Copy-Item -LiteralPath $src -Destination $dst -Force
    Write-Host "[latexdiff] Saved: $dst"
} else {
    Write-Host "[latexdiff] WARNING: PDF not found at expected path: $src"
}
