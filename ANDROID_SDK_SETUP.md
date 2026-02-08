# ⚠️ Android SDK Not Found - Setup Required

## The Issue
Gradle cannot find your Android SDK location. You need to configure it.

---

## 🔧 Solution 1: Set ANDROID_HOME Environment Variable (Recommended)

### Find Your Android SDK Location

Common locations on Windows:
```
C:\Users\YourName\AppData\Local\Android\Sdk
C:\Android\Sdk
D:\Android\Sdk
```

### Set Environment Variable

**Option A: Using System Settings (Permanent)**
1. Press `Win + X` → Select **System**
2. Click **Advanced system settings**
3. Click **Environment Variables**
4. Under **User variables**, click **New**
5. Variable name: `ANDROID_HOME`
6. Variable value: `C:\Users\YourName\AppData\Local\Android\Sdk`
7. Click **OK** on all dialogs
8. **Restart your terminal/command prompt**

**Option B: Using Command Line (Temporary)**
```cmd
REM For current session only
set ANDROID_HOME=C:\Users\YourName\AppData\Local\Android\Sdk

REM Or use PowerShell
$env:ANDROID_HOME="C:\Users\YourName\AppData\Local\Android\Sdk"
```

---

## 🔧 Solution 2: Create local.properties File (Alternative)

Create a `local.properties` file in your project root with your SDK path:

### Step 1: Find Your SDK Path
Open Android Studio:
1. **File** → **Settings** (or `Ctrl + Alt + S`)
2. Go to **Appearance & Behavior** → **System Settings** → **Android SDK**
3. Look at **SDK Location** field
4. Copy that path

### Step 2: Create local.properties
```cmd
REM Navigate to project root
cd C:\Users\plner\AndroidStudioProjects\btsec-testtool\btsec-testtool

REM Create local.properties file
echo sdk.dir=C:\\Users\\YourName\\AppData\\Local\\Android\\Sdk > local.properties
```

**Example**:
```properties
sdk.dir=C\\:\\Users\\plner\\AndroidStudioProjects\\btsec-testtool\\btsec-testtool
```

---

## ✅ Verify Setup

After configuring, verify:

```cmd
REM Check ANDROID_HOME is set
echo %ANDROID_HOME%

REM Check if SDK directory exists
dir "%ANDROID_HOME%"

REM Try building again
gradlew.bat assembleDebug
```

---

## 🎯 Once Configured, Run Tests Again

```cmd
scripts\test.bat
```

---

## 💡 Quick Setup for Android Studio Users

1. Open Android Studio
2. Open this project
3. Android Studio will automatically create `local.properties`
4. Try running tests again

---

**Need help finding your SDK?** Open Android Studio and check:
**Settings** → **Appearance & Behavior** → **System Settings** → **Android SDK**
The SDK path is shown at the top.
