import os
import fnmatch
import subprocess
import sys
import platform
import locale
import re

def sanitize_path(path):
    """Sanitize Windows paths for subprocess calls"""
    if platform.system() == "Windows":
        return os.path.normpath(path).replace('\\', '/')
    return path

def get_tree_structure(project_dir):
    """Get directory tree structure in a cross-platform way"""
    project_dir = sanitize_path(project_dir)

    if platform.system() == "Windows":
        try:
            # Use Windows' built-in tree command via cmd (more reliable than direct invocation)
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.run(['cmd', '/c', 'tree', '/F', '/A'],
                                 cwd=project_dir,
                                 capture_output=True,
                                 text=True,
                                 encoding=locale.getpreferredencoding(),
                                 startupinfo=si,
                                 check=True)
            # Remove the first two lines of Windows tree output
            tree_lines = result.stdout.split('\n')[2:]
            return '\n'.join(tree_lines)
        except (subprocess.CalledProcessError, Exception) as e:
            print(f"Tree command failed: {e}. Using manual tree generation.")
            return create_manual_tree(project_dir)
    else:
        try:
            exclude_pattern = 'node_modules|.vscode|venv|temp|uploads|output|datastore|input|__pycache__|code.txt|code_extractor.py|target|.idea|.mvn|.settings|bin|out|logs|vendor|local|test'
            result = subprocess.run(['tree', '-I', exclude_pattern],
                                 cwd=project_dir,
                                 capture_output=True,
                                 text=True,
                                 check=True)
            return result.stdout
        except (FileNotFoundError, subprocess.CalledProcessError):
            return create_manual_tree(project_dir)

def create_manual_tree(start_path):
    """Create a tree-like structure manually if tree command fails"""
    output = []
    exclude_dirs = {
        'node_modules', '.vscode', 'venv', 'temp', 'uploads', 'output',
        'datastore', 'input', '__pycache__', 'target', '.idea', '.mvn',
        '.settings', 'bin', 'out', 'logs', 'dist', 'vendor',
        'coverage', '.next', '.husky', '.swc', 'build',
        '.turbo', '.tailwind', 'storybook'
    }

    try:
        for root, dirs, files in os.walk(start_path):
            # Remove excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs and not d.startswith('.')]

            # Calculate current depth and prepare indentation
            level = root[len(start_path):].count(os.sep)
            indent = '│   ' * (level - 1) + '├── ' if level > 0 else ''

            # Add directory name
            if level > 0:
                dirname = os.path.basename(root)
                output.append(f"{indent}{dirname}")

            # Add files
            subindent = '│   ' * level + '├── '
            for f in sorted(files):
                if not f.startswith('.') and not any(f.endswith(ext) for ext in ['.pyc', '.pyo']):
                    output.append(f"{subindent}{f}")

        return '\n'.join(output)
    except Exception as e:
        print(f"Error creating manual tree: {e}")
        return "Error creating directory tree"

def is_media_file(filename):
    media_extensions = {
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp',  # Images
        '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv',  # Videos
        '.mp3', '.wav', '.ogg', '.flac', '.aac',  # Audio
        '.svg',  # Vector graphics
    }
    return os.path.splitext(filename)[1].lower() in media_extensions

def is_critical_config(filename):
    """Check if file is a critical configuration that should always be included"""
    critical_files = {
        # TypeScript/Next.js config
        'tsconfig.json', 'tsconfig.jest.json', 'tsconfig.node.json',
        'next.config.ts', 'next.config.js',
        # Build tools
        'vite.config.js', 'vite.config.ts',
        'webpack.config.js', 'webpack.config.ts',
        # Linting & Formatting
        '.eslintrc.js', '.eslintrc.json', '.eslintrc.mjs',
        '.prettierrc', '.prettierrc.json', '.prettierrc.js',
        # CSS/PostCSS
        'postcss.config.js', 'postcss.config.mjs',
        'tailwind.config.js', 'tailwind.config.ts',
        # Environment templates (NOT the actual .env file)
        '.env.example', '.env.testing', '.env.local.example',
        # Jest/Test config
        'jest.config.js', 'jest.config.ts',
        # PHP/Laravel specific
        'vite.config.js', 'phpunit.xml', 'phpstan.neon',
    }
    return filename in critical_files


def should_exclude_env_file(filename):
    """Exclude real environment files (potential secrets), but allow safe templates."""
    if not filename.startswith('.env'):
        return False
    return not is_critical_config(filename)


def normalize_content(content, compact_output):
    """Reduce token/size overhead while preserving code structure."""
    if not compact_output:
        return content

    # Remove trailing whitespace per line
    content = re.sub(r"[ \t]+(?=\r?$)", "", content, flags=re.MULTILINE)

    # Collapse 3+ consecutive blank lines into a single blank line
    content = re.sub(r"(\r?\n){3,}", "\n\n", content)

    # Trim leading/trailing excessive newlines
    return content.strip("\n")


def redact_secrets(content, filename):
    """Lightweight redaction for config-like files to avoid leaking secrets.

    This is intentionally conservative: it only redacts obvious KEY=VALUE or KEY: VALUE patterns.
    """
    lower = filename.lower()
    is_config_like = any(lower.endswith(ext) for ext in ('.env', '.yml', '.yaml', '.json')) or filename.startswith('.env')
    if not is_config_like:
        return content

    secret_key_re = re.compile(
        r"(?im)^(\s*)([A-Z0-9_]*?(?:PASSWORD|PASS|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY|CLIENT_SECRET|DB_PASSWORD|JWT_SECRET)[A-Z0-9_]*)(\s*[:=]\s*)(.+)$"
    )

    def _mask(match):
        return f"{match.group(1)}{match.group(2)}{match.group(3)}[REDACTED]"

    return secret_key_re.sub(_mask, content)

def detect_project_type(project_dir):
    """Detect if project is monorepo (has both backend/ and frontend/)"""
    has_backend = os.path.isdir(os.path.join(project_dir, 'backend'))
    has_frontend = os.path.isdir(os.path.join(project_dir, 'frontend'))
    return 'monorepo' if (has_backend and has_frontend) else 'single'

def process_files(project_dir, output_file, compact_output=True, include_tree=False):
    if os.path.exists(output_file):
        try:
            os.remove(output_file)
            print(f"Removed existing output file: {output_file}")
        except OSError as e:
            print(f"Error removing existing output file: {e}")
            sys.exit(1)

    # Detect project type and structure
    project_type = detect_project_type(project_dir)
    has_backend = os.path.isdir(os.path.join(project_dir, 'backend'))
    has_frontend = os.path.isdir(os.path.join(project_dir, 'frontend'))

    exclude_files = {
        'package-lock.json', 'yarn.lock',
        'README.md', '.gitignore', 'babel.config.js',
        'requirements.txt', 'Pipfile', 'Pipfile.lock', 'setup.py', 'MANIFEST.in',
        'code_extractor.py', 'code.txt', 'code_extractor_back.py',
        'code_extractor_front.py', 'TODO', 'toctoc-secrets.yaml',
        '.phpunit.result.cache', '.eslintignore', '.prettierignore',
        'Procfile', '.ruby-version', '.python-version', '.nvmrc'
    }
    # More granular exclusion patterns - be specific to avoid blocking critical configs
    exclude_patterns = [
        '*.md', '*.lock', '*.log', '*.pyc', '*.pyo', '*.map', '*.min.*',
        '*.tsbuildinfo',
        '*.swp', '*.swo', '.git*', 'LICENSE*', '.DS_Store', '*.tmp',
        # Exclude .env files but CRITICAL configs are handled separately via is_critical_config()
        '.env', '.env.local', '.env.*.local',
        # Package manager files (but NOT tsconfig which is config)
        'package-lock.json', 'yarn.lock',
        # Build outputs
        '*.bundle.js', '*.bundle.css',
    ]
    exclude_dirs = {
        'node_modules', 'venv', 'temp', 'uploads', 'output',
        'datastore', 'input', '__pycache__', 'dist', 'vendor',
        'local', 'coverage', '.next', '.nuxt', '.husky', '.swc',
        'build', '.turbo', '.cache', '.tailwind',
        'storybook', '.serverless', '.vercel', '.env.local'
    }

    try:
        with open(output_file, 'w', encoding='utf-8') as out:
            # Minimal header for LLM ingestion
            out.write("PROJECT: SHOWMETEXT\n")
            out.write(f"TYPE: {project_type}\n")
            if project_type == 'monorepo':
                out.write(f"HAS_BACKEND: {str(has_backend).lower()}\n")
                out.write(f"HAS_FRONTEND: {str(has_frontend).lower()}\n")
            out.write("\n")

            if include_tree:
                out.write("TREE:\n")
                out.write(get_tree_structure(project_dir))
                out.write("\n\n")

            # Process directories in order: root first, then backend, then frontend
            dirs_to_process = []
            if project_type == 'monorepo':
                dirs_to_process.append(('root', project_dir))
                if has_backend:
                    dirs_to_process.append(('backend', os.path.join(project_dir, 'backend')))
                if has_frontend:
                    dirs_to_process.append(('frontend', os.path.join(project_dir, 'frontend')))
            else:
                dirs_to_process.append(('root', project_dir))

            for section_name, section_dir in dirs_to_process:
                if project_type == 'monorepo':
                    out.write(f"SECTION:{section_name.upper()}\n")

                for root, dirs, files in os.walk(section_dir):
                    # In monorepo root walk, avoid recursing into backend/frontend (they are processed separately)
                    if project_type == 'monorepo' and section_name == 'root':
                        dirs[:] = [d for d in dirs if d not in {'backend', 'frontend'}]

                    dirs[:] = [d for d in dirs if not d.startswith('.') or d == '.env']
                    dirs[:] = [d for d in dirs if d not in exclude_dirs]

                    for file in sorted(files):
                        # Skip env-like files (potential secrets), except safe templates
                        if should_exclude_env_file(file):
                            continue

                        # Skip dotfiles except critical configs
                        if file.startswith('.') and not is_critical_config(file):
                            continue

                        # Check exclude lists
                        if file in exclude_files:
                            continue

                        # Skip patterns (except for critical configs)
                        if not is_critical_config(file) and any(fnmatch.fnmatch(file, pattern) for pattern in exclude_patterns):
                            continue

                        # Skip media files
                        if is_media_file(file):
                            continue

                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, project_dir)


                        # Compact, machine-friendly boundaries
                        out.write(f"FILE:{relative_path}\n")

                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                                content = redact_secrets(content, file)
                                content = normalize_content(content, compact_output)
                                # Limit file size for output (max 50KB per file for reasonable context)
                                if len(content) > 50000:
                                    out.write(f"TRUNCATED:true SIZE:{len(content)}\n")
                                    out.write(content[:50000])
                                else:
                                    out.write(content)
                        except UnicodeDecodeError:
                            out.write("BINARY:true\n")
                        except IOError as e:
                            out.write(f"ERROR:{e}\n")

                        out.write("\n")

                if project_type == 'monorepo':
                    out.write("\n")

        print(f"Script completed. Output saved to {output_file}")
        print(f"Project Type: {project_type}")
        if project_type == 'monorepo':
            print(f"  - Backend: {'Yes' if has_backend else 'No'}")
            print(f"  - Frontend: {'Yes' if has_frontend else 'No'}")
    except IOError as e:
        print(f"Error writing to output file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.getcwd()
    output_file = os.path.join(script_dir, "code.txt")

    # Defaults optimized for LLM ingestion: compact output, no tree.
    compact_output = True
    include_tree = False

    if '--pretty' in sys.argv:
        compact_output = False
        include_tree = True
    if '--tree' in sys.argv:
        include_tree = True

    process_files(project_dir, output_file, compact_output=compact_output, include_tree=include_tree)
