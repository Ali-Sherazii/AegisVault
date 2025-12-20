# GitHub Repository Setup Instructions

This guide will help you create a GitHub repository for your WAF project while excluding datasets and model files.

## Prerequisites

1. **Git installed** on your machine
   - Check if installed: `git --version`
   - Download from: https://git-scm.com/downloads

2. **GitHub account**
   - Create one at: https://github.com

## Step-by-Step Instructions

### Step 1: Initialize Git Repository (if not already done)

Open your terminal/command prompt in the project root directory (`MLproj`) and run:

```bash
git init
```

### Step 2: Verify .gitignore File

The `.gitignore` file has been updated to exclude:
- ✅ All dataset files (`.csv`, `.xml`, `.xlsx`)
- ✅ All model files (`.pkl`, `.joblib`, `.npz`, `.h5`, etc.)
- ✅ Dataset directories (`waf/Datasets/`)
- ✅ Training data files
- ✅ Large JSON files in Preprocessing folder
- ✅ Python cache files (`__pycache__/`)
- ✅ Virtual environments
- ✅ IDE files

**Note:** Configuration files like `waf_settings.json` will be included.

### Step 3: Check What Will Be Committed

Before committing, check which files will be added:

```bash
git status
```

This will show you all files that will be tracked. Verify that:
- ❌ No `.pkl`, `.joblib`, `.npz` files appear
- ❌ No `.csv`, `.xml` files from `waf/Datasets/` appear
- ❌ No large JSON files from `waf/Preprocessing/` appear
- ✅ Your source code files (`.py`, `.ipynb`, `.yaml`, etc.) appear
- ✅ Configuration files appear

### Step 4: Add Files to Staging

Add all files that should be tracked:

```bash
git add .
```

Or add files selectively:

```bash
git add *.py
git add *.ipynb
git add *.yaml
git add *.json  # This will only add waf_settings.json (others are ignored)
git add *.txt
git add *.md
git add *.html
git add *.css
git add *.js
```

### Step 5: Create Initial Commit

```bash
git commit -m "Initial commit: WAF project without datasets and models"
```

### Step 6: Create GitHub Repository

1. Go to https://github.com and sign in
2. Click the **"+"** icon in the top right corner
3. Select **"New repository"**
4. Fill in the details:
   - **Repository name**: `waf-project` (or your preferred name)
   - **Description**: "AI Web Application Firewall with ML-based attack detection"
   - **Visibility**: Choose Public or Private
   - **DO NOT** initialize with README, .gitignore, or license (we already have these)
5. Click **"Create repository"**

### Step 7: Connect Local Repository to GitHub

After creating the repository, GitHub will show you commands. Use these:

```bash
# Add the remote repository (replace YOUR_USERNAME and REPO_NAME)
git remote add origin https://github.com/YOUR_USERNAME/REPO_NAME.git

# Rename branch to main (if needed)
git branch -M main

# Push your code to GitHub
git push -u origin main
```

**Example:**
```bash
git remote add origin https://github.com/johndoe/waf-project.git
git branch -M main
git push -u origin main
```

### Step 8: Verify Upload

1. Refresh your GitHub repository page
2. Verify that:
   - ✅ Source code files are present
   - ✅ Notebooks are present
   - ✅ Configuration files are present
   - ❌ No dataset files (`.csv`, `.xml`) are present
   - ❌ No model files (`.pkl`, `.joblib`) are present

## Additional Commands

### View What's Being Ignored

```bash
git status --ignored
```

### Remove Already Tracked Files (if needed)

If you accidentally committed files that should be ignored:

```bash
# Remove from Git tracking but keep local files
git rm --cached waf/Datasets/*.csv
git rm --cached waf/Training/*.pkl
git commit -m "Remove dataset and model files from tracking"
```

### Update .gitignore Later

If you need to add more exclusions later:

1. Edit `.gitignore` file
2. Run `git add .gitignore`
3. Run `git commit -m "Update .gitignore"`
4. Run `git push`

## Troubleshooting

### Issue: "Large files detected"
If GitHub warns about large files:
- Ensure `.gitignore` properly excludes large files
- Use `git rm --cached <file>` to remove large files from history if already committed

### Issue: Authentication Required
If prompted for credentials:
- Use a **Personal Access Token** instead of password
- Generate one at: GitHub Settings → Developer settings → Personal access tokens

### Issue: Files Still Showing
If ignored files still appear:
```bash
# Clear Git cache
git rm -r --cached .
git add .
git commit -m "Update .gitignore and remove cached files"
```

## Next Steps

After pushing to GitHub:

1. **Add a README** (if not already present) with:
   - Project description
   - Installation instructions
   - Usage examples
   - Note about datasets/models being excluded

2. **Add a LICENSE** file if needed

3. **Create a `.github/workflows`** folder for CI/CD if desired

4. **Add collaborators** if working in a team

## Important Notes

⚠️ **Never commit sensitive data:**
- API keys
- Passwords
- Database credentials
- Personal information

⚠️ **Dataset and Model Files:**
- Keep these locally or use Git LFS for large files
- Document where to download datasets in README
- Consider using cloud storage (Google Drive, Dropbox) for sharing datasets

---

**Need Help?** Check Git documentation: https://git-scm.com/doc

