@echo off
chcp 65001 >nul
echo ========================================
echo   智读 · 打包 Windows exe
echo ========================================
echo.

where python >nul 2>nul
if errorlevel 1 (
  echo [错误] 未找到 python，请先安装 Python 3.10+ 并勾选 Add to PATH
  pause
  exit /b 1
)

echo [1/3] 安装 PyInstaller ...
python -m pip install -U pyinstaller -r requirements.txt -q
if errorlevel 1 (
  echo [错误] 安装 PyInstaller 失败
  pause
  exit /b 1
)

echo [2/3] 开始打包（约 1～3 分钟）...
python -m PyInstaller --noconfirm zhidu.spec
if errorlevel 1 (
  echo [错误] 打包失败
  pause
  exit /b 1
)

echo [3/3] 整理输出 ...
if not exist release mkdir release
copy /Y dist\智读.exe release\智读.exe >nul
if exist public_pdfs xcopy /E /I /Y public_pdfs release\public_pdfs >nul
echo.
echo ========================================
echo   完成！可执行文件：
echo   release\智读.exe
echo ========================================
echo 双击运行后浏览器会自动打开。
echo 管理员: admin / ChangeMe@2026
echo.
pause
