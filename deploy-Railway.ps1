# railway-deploy.ps1
Write-Host "🚀 Deploying Spiritual Center to Railway..." -ForegroundColor Cyan

# Check if Railway CLI is installed
$railwayCheck = Get-Command railway -ErrorAction SilentlyContinue
if (-not $railwayCheck) {
    Write-Host "❌ Railway CLI not found. Installing..." -ForegroundColor Yellow
    npm install -g @railway/cli
}

# Login to Railway (if not already logged in)
Write-Host "🔐 Checking Railway login..." -ForegroundColor Yellow
railway status

# Add all files and commit
Write-Host "📦 Committing changes..." -ForegroundColor Yellow
git add .
git commit -m "Deploy Spiritual Center $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -m "Auto-deployment to Railway"

# Push to GitHub
Write-Host "📤 Pushing to GitHub..." -ForegroundColor Yellow
git push origin main

# Deploy to Railway
Write-Host "🚀 Deploying to Railway..." -ForegroundColor Cyan
railway up

Write-Host "✅ Spiritual-center deployment complete!" -ForegroundColor Green
Write-Host "🌐 Your app is live at: https://Spiritual-center.up.railway.app" -ForegroundColor Cyan
