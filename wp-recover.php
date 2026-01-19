<?php
/**
 * WP Recover & Scan
 * 
 * Single file script to:
 * 1. Clean existing WP core files (preserving wp-config.php)
 * 2. Download and reinstall latest WordPress
 * 3. Scan wp-content for suspicious files
 */

// Increase execution time and memory for heavy operations
@ini_set('max_execution_time', 300);
@ini_set('memory_limit', '256M');

define('WP_RECOVER_VERSION', '1.0.0');
define('SELF_FILENAME', basename(__FILE__));

// --- Backend Logic ---

if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    $response = ['success' => false, 'message' => '', 'data' => []];

    try {
        switch ($_GET['action']) {
            case 'cleanup':
                // step 1: Remove core folders and files
                $root = __DIR__;
                $preserve = ['wp-config.php', SELF_FILENAME, 'wp-content', '.htaccess', 'robots.txt'];
                $deleted = [];

                // Delete wp-admin and wp-includes
                foreach (['wp-admin', 'wp-includes'] as $dir) {
                    $path = $root . '/' . $dir;
                    if (is_dir($path)) {
                        recursiveDelete($path);
                        $deleted[] = $dir . '/';
                    }
                }

                // Delete root .php files
                $files = glob($root . '/*.php');
                foreach ($files as $file) {
                    $basename = basename($file);
                    if (!in_array($basename, $preserve)) {
                        unlink($file);
                        $deleted[] = $basename;
                    }
                }

                $response['success'] = true;
                $response['message'] = 'Core files cleaned successfully.';
                $response['data'] = ['deleted' => $deleted];
                break;

            case 'download':
                // step 2: Download WordPress
                $url = 'https://wordpress.org/latest.zip';
                $zipFile = __DIR__ . '/latest.zip';
                
                $fp = fopen($zipFile, 'w+');
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_TIMEOUT, 300);
                curl_setopt($ch, CURLOPT_FILE, $fp);
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                $exec = curl_exec($ch);
                $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                curl_close($ch);
                fclose($fp);

                if ($exec && $code == 200) {
                    $response['success'] = true;
                    $response['message'] = 'WordPress latest.zip downloaded.';
                } else {
                    throw new Exception("Failed to download WordPress. HTTP Code: $code");
                }
                break;

            case 'extract':
                // step 3: Extract and Move
                $zipFile = __DIR__ . '/latest.zip';
                if (!file_exists($zipFile)) {
                    throw new Exception("latest.zip not found.");
                }

                $zip = new ZipArchive;
                if ($zip->open($zipFile) === TRUE) {
                    $zip->extractTo(__DIR__ . '/temp_wp_extract');
                    $zip->close();
                    
                    // Move files from temp_wp_extract/wordpress to root
                    $source = __DIR__ . '/temp_wp_extract/wordpress';
                    $dest = __DIR__;
                    
                    if (is_dir($source)) {
                        moveDirContents($source, $dest);
                    }
                    
                    // Cleanup
                    recursiveDelete(__DIR__ . '/temp_wp_extract');
                    unlink($zipFile);

                    $response['success'] = true;
                    $response['message'] = 'WordPress extracted and installed.';
                } else {
                    throw new Exception("Failed to open zip archive.");
                }
                break;

            case 'scan':
                // step 4: Scan wp-content
                $scanResults = scanWpContent(__DIR__ . '/wp-content');
                $response['success'] = true;
                $response['message'] = 'Scan completed.';
                $response['data'] = $scanResults;
                break;

            default:
                throw new Exception("Invalid action.");
        }
    } catch (Exception $e) {
        $response['message'] = $e->getMessage();
    }

    echo json_encode($response);
    exit;
}

// --- Helper Functions ---

function recursiveDelete($dir) {
    if (!is_dir($dir)) return;
    $files = array_diff(scandir($dir), array('.', '..'));
    foreach ($files as $file) {
        (is_dir("$dir/$file")) ? recursiveDelete("$dir/$file") : unlink("$dir/$file");
    }
    return rmdir($dir);
}

function moveDirContents($src, $dst) {
    $dir = opendir($src);
    @mkdir($dst);
    while (false !== ($file = readdir($dir))) {
        if (($file != '.') && ($file != '..')) {
            if (is_dir($src . '/' . $file)) {
                // Check if dest dir exists, if not create it, else recursive move
                if (!file_exists($dst . '/' . $file)) {
                     rename($src . '/' . $file, $dst . '/' . $file);
                } else {
                    moveDirContents($src . '/' . $file, $dst . '/' . $file);
                }
            } else {
                // Don't overwrite wp-config.php if it happens to be in src (unlikely for core zip)
                // Don't overwrite wp-recover.php
                if ($file !== 'wp-config.php' && $file !== 'wp-recover.php') {
                    rename($src . '/' . $file, $dst . '/' . $file);
                }
            }
        }
    }
    closedir($dir);
}

function scanWpContent($dir) {
    $suspicious = [];
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));
    
    foreach ($iterator as $file) {
        if ($file->isDir()) {
            if (substr($file->getFilename(), 0, 1) === '.' && !in_array($file->getFilename(), ['.', '..'])) {
                 $suspicious[] = [
                    'type' => 'folder',
                    'path' => $file->getPathname(),
                    'reason' => 'Hidden directory'
                ];
            }
            continue;
        }

        $filename = $file->getFilename();
        $path = $file->getPathname();
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        // Check 1: PHP files in uploads (very bad)
        if (strpos($path, 'wp-content/uploads') !== false && $ext === 'php') {
            $suspicious[] = [
                'type' => 'file',
                'path' => $path,
                'reason' => 'PHP file in uploads directory (High Risk)'
            ];
        }

        // Check 2: Permissions
        $perms = substr(sprintf('%o', fileperms($path)), -4);
        if ($perms === '0777') {
             $suspicious[] = [
                'type' => 'permission',
                'path' => $path,
                'reason' => '777 Permissions'
            ];
        }

        // Check 3: Content Heuristics (only for PHP files)
        if ($ext === 'php') {
            $content = file_get_contents($path, false, null, 0, 2048); // read first 2kb
            if (
                strpos($content, 'eval(base64_decode') !== false ||
                strpos($content, 'eval(gzinflate') !== false ||
                strpos($content, 'GLOBALS[\'') !== false || // naive check for simple obfuscation
                strpos($content, '\x65\x76\x61\x6c') !== false // hex eval
            ) {
                 $suspicious[] = [
                    'type' => 'code',
                    'path' => $path,
                    'reason' => 'Suspicious code pattern (eval/base64/obfuscation)'
                ];
            }
        }
    }
    return $suspicious;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WP Recover & Scan Tool</title>
    <!-- CDN Assets -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background-color: #1a1d20; color: #e9ecef; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .container { max-width: 800px; margin-top: 50px; }
        .card { background-color: #212529; border: 1px solid #343a40; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
        .card-header { border-bottom: 1px solid #343a40; background: #2c3034; }
        .btn-primary { background-color: #0d6efd; border-color: #0d6efd; }
        .btn-primary:hover { background-color: #0b5ed7; border-color: #0a58ca; }
        .log-window { background: #000; color: #00ff00; font-family: monospace; height: 300px; overflow-y: auto; padding: 10px; border-radius: 5px; border: 1px solid #333; margin-top: 20px; font-size: 0.9em; }
        .log-entry { margin-bottom: 5px; border-bottom: 1px solid #111; padding-bottom: 2px; }
        .log-entry.error { color: #ff4444; }
        .log-entry.success { color: #00ff00; }
        .log-entry.warning { color: #ffbb33; }
        .progress { height: 25px; background-color: #343a40; margin-top: 20px; }
        .progress-bar { transition: width 0.5s ease; font-weight: bold; }
        .scan-item { padding: 5px; border-bottom: 1px solid #444; }
        .scan-item:last-child { border-bottom: none; }
        .badge-risk { background-color: #dc3545; color: white; }
    </style>
</head>
<body>

<div class="container">
    <div class="card">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h4 class="m-0"><i class="fa-brands fa-wordpress me-2"></i>WP Recover & Scan</h4>
            <span class="badge bg-secondary">v<?php echo WP_RECOVER_VERSION; ?></span>
        </div>
        <div class="card-body">
            
            <div class="alert alert-warning">
                <i class="fa-solid fa-triangle-exclamation me-2"></i>
                <strong>Warning:</strong> This process will <strong>DELETE</strong> the <code>wp-admin</code> and <code>wp-includes</code> directories, and root <code>.php</code> files (except <code>wp-config.php</code>). Make sure you have backups!
            </div>

            <p class="text-secondary">This tool will reinstall a fresh copy of WordPress and scan your <code>wp-content</code> folder for common malware indicators.</p>

            <button id="startBtn" class="btn btn-primary btn-lg w-100">
                <i class="fa-solid fa-play me-2"></i> Start Recovery Process
            </button>

            <div class="progress d-none" id="progressContainer">
                <div id="progressBar" class="progress-bar progress-bar-striped progress-bar-animated bg-success" role="progressbar" style="width: 0%">0%</div>
            </div>

            <div class="log-window" id="logWindow">
                <div class="log-entry">> Ready to start...</div>
            </div>

            <div id="reportArea" class="mt-4 d-none">
                <h5 class="border-bottom pb-2 mb-3">Scan Report</h5>
                <div id="scanResults" class="list-group list-group-flush"></div>
            </div>

        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
    const logWindow = document.getElementById('logWindow');
    const progressBar = document.getElementById('progressBar');
    const startBtn = document.getElementById('startBtn');
    const progressContainer = document.getElementById('progressContainer');
    const reportArea = document.getElementById('reportArea');
    const scanResults = document.getElementById('scanResults');

    function log(msg, type = 'info') {
        const div = document.createElement('div');
        div.className = 'log-entry ' + type;
        div.innerText = '> ' + msg;
        logWindow.appendChild(div);
        logWindow.scrollTop = logWindow.scrollHeight;
    }

    function updateProgress(percent, text) {
        progressBar.style.width = percent + '%';
        progressBar.innerText = percent + '%';
        if (text) log(text);
    }

    async function runStep(action, stepName, progress) {
        log(`Starting: ${stepName}...`);
        try {
            const response = await fetch('?action=' + action);
            const data = await response.json();
            
            if (data.success) {
                updateProgress(progress, `Completed: ${stepName}`);
                return data;
            } else {
                throw new Error(data.message);
            }
        } catch (e) {
            log(`Error in ${stepName}: ${e.message}`, 'error');
            throw e;
        }
    }

    startBtn.addEventListener('click', async () => {
        if (!confirm('Are you sure you want to proceed? This will replace core WordPress files.')) return;

        startBtn.disabled = true;
        progressContainer.classList.remove('d-none');
        reportArea.classList.add('d-none');
        scanResults.innerHTML = '';
        
        try {
            // Step 1: Cleanup
            await runStep('cleanup', 'Cleaning Core Files', 25);
            
            // Step 2: Download
            await runStep('download', 'Downloading WordPress', 50);

            // Step 3: Extract & Install
            await runStep('extract', 'Extracting & Installing', 75);

            // Step 4: Scan
            log('Starting Malware Scan (this may take a moment)...');
            const scanData = await runStep('scan', 'Security Scan', 100);
            
            progressBar.classList.remove('progress-bar-animated');
            progressBar.classList.add('bg-success');
            log('Process Finished Successfully!', 'success');

            // Render Report
            if (scanData.data && scanData.data.length > 0) {
                renderReport(scanData.data);
            } else {
                log('Scan finished clean. No obvious threats found.', 'success');
            }

        } catch (e) {
            progressBar.classList.remove('bg-success');
            progressBar.classList.add('bg-danger');
            log('Process Failed!', 'error');
            startBtn.disabled = false;
        }
    });

    function renderReport(items) {
        reportArea.classList.remove('d-none');
        let html = '';
        items.forEach(item => {
            let icon = 'fa-file-code';
            if (item.type === 'folder') icon = 'fa-folder-open';
            if (item.type === 'permission') icon = 'fa-lock-open';

            html += `
                <div class="list-group-item bg-dark text-light border-secondary">
                    <div class="d-flex w-100 justify-content-between">
                        <h6 class="mb-1 text-danger"><i class="fa-solid ${icon} me-2"></i>${item.reason}</h6>
                        <small>${item.type}</small>
                    </div>
                    <p class="mb-1 font-monospace small text-break opacity-75">${item.path}</p>
                </div>
            `;
        });
        scanResults.innerHTML = html;
    }

</script>
</body>
</html>
