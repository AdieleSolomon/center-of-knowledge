Write-Host "🚀 Deploying project updates..." -ForegroundColor Cyan

git add .
git commit -m "Deploy: Spiritual Center $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
git push origin main

Write-Host "📦 Triggering Render deployment..." -ForegroundColor Yellow
render deploy

Write-Host "✅ Deployment complete!" -ForegroundColor Green
Write-Host "🌐 Backend: https://spiritual-center.onrender.com" -ForegroundColor Cyan
Write-Host "📱 Frontend: https://spiritualcenter-5c36s19bx-solomon-adieles-projects.vercel.app" -ForegroundColor Cyan