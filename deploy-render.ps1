# deploy-render.ps1
Write-Host "🚀 Deploying Spiritual Center to Render..." -ForegroundColor Cyan

# Add all files
Write-Host "📦 Adding files to git..." -ForegroundColor Yellow
git add .

# Commit changes
Write-Host "💾 Committing changes..." -ForegroundColor Yellow
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm"
git commit -m "Deploy to Render: Spiritual Center $timestamp"

# Push to GitHub
Write-Host "📤 Pushing to GitHub..." -ForegroundColor Yellow
git push origin main

Write-Host "✅ Code pushed to GitHub!" -ForegroundColor Green
Write-Host ""
Write-Host "🎯 NEXT STEPS:" -ForegroundColor Magenta
Write-Host "1. Go to: https://render.com" -ForegroundColor White
Write-Host "2. Click 'New +' → 'Web Service'" -ForegroundColor White
Write-Host "3. Connect your GitHub repository" -ForegroundColor White
Write-Host "4. Use these settings:" -ForegroundColor White
Write-Host "   - Name: spiritual-center" -ForegroundColor Gray
Write-Host "   - Environment: Node" -ForegroundColor Gray
Write-Host "   - Region: Ohio (or closest to you)" -ForegroundColor Gray
Write-Host "   - Branch: main" -ForegroundColor Gray
Write-Host "   - Build Command: npm install" -ForegroundColor Gray
Write-Host "   - Start Command: npm start" -ForegroundColor Gray
Write-Host "5. Add environment variables:" -ForegroundColor White
Write-Host "   - NODE_ENV: production" -ForegroundColor Gray
Write-Host "   - JWT_SECRET: your-secret-key-here" -ForegroundColor Gray
Write-Host "6. Click 'Create Web Service'" -ForegroundColor White
Write-Host ""
Write-Host "🌐 Your app will be live at: https://spiritual-center.onrender.com" -ForegroundColor Cyan