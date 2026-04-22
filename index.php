<?php
session_start();

$base_dir = realpath(dirname(__FILE__));
$current_dir = isset($_GET['dir']) ? realpath($_GET['dir']) : $base_dir;

if ($current_dir === false || strpos($current_dir, $base_dir) !== 0) {
    $current_dir = $base_dir;
}

$message = '';

if (isset($_GET['download'])) {
    $file = realpath($_GET['download']);
    if ($file && strpos($file, $base_dir) === 0 && is_file($file)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="'.basename($file).'"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($file));
        readfile($file);
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['action'])) {
        $action = $_POST['action'];

        if ($action === 'upload' && isset($_FILES['file'])) {
            $target = $current_dir . DIRECTORY_SEPARATOR . basename($_FILES['file']['name']);
            if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
                $message = "File uploaded successfully.";
            } else {
                $message = "Upload failed.";
            }
        } elseif ($action === 'mkdir' && !empty($_POST['foldername'])) {
            $new_dir = $current_dir . DIRECTORY_SEPARATOR . $_POST['foldername'];
            if (!file_exists($new_dir) && mkdir($new_dir)) {
                $message = "Directory created.";
            } else {
                $message = "Failed to create directory.";
            }
        } elseif ($action === 'delete' && !empty($_POST['target'])) {
            $target = realpath($_POST['target']);
            if ($target && strpos($target, $base_dir) === 0 && $target !== $base_dir) {
                if (is_dir($target)) {
                    rmdir($target) ? $message = "Directory deleted." : $message = "Failed to delete directory (must be empty).";
                } else {
                    unlink($target) ? $message = "File deleted." : $message = "Failed to delete file.";
                }
            }
        } elseif ($action === 'rename' && !empty($_POST['old_name']) && !empty($_POST['new_name'])) {
            $old = realpath($_POST['old_name']);
            $new = dirname($old) . DIRECTORY_SEPARATOR . basename($_POST['new_name']);
            if ($old && strpos($old, $base_dir) === 0 && rename($old, $new)) {
                $message = "Renamed successfully.";
            } else {
                $message = "Rename failed.";
            }
        }
    }
    header("Location: ?dir=" . urlencode($current_dir));
    exit;
}

$items = scandir($current_dir);
$directories = [];
$files = [];

foreach ($items as $item) {
    if ($item === '.' || ($item === '..' && $current_dir === $base_dir)) continue;
    $path = $current_dir . DIRECTORY_SEPARATOR . $item;
    if (is_dir($path)) {
        $directories[] = $item;
    } else {
        $files[] = $item;
    }
}

function formatSize($bytes) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= pow(1024, $pow);
    return round($bytes, 2) . ' ' . $units[$pow];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP File Manager</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; margin: 0; padding: 20px; color: #333; }
        .container { max-width: 1000px; margin: 0 auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1 { margin-top: 0; font-size: 24px; color: #2c3e50; }
        .breadcrumb { padding: 10px; background: #ecf0f1; border-radius: 4px; margin-bottom: 20px; word-break: break-all; }
        .breadcrumb a { color: #2980b9; text-decoration: none; }
        .breadcrumb a:hover { text-decoration: underline; }
        .controls { display: flex; gap: 20px; margin-bottom: 20px; flex-wrap: wrap; }
        .control-group { background: #f9f9f9; padding: 15px; border-radius: 6px; border: 1px solid #eee; flex: 1; min-width: 250px; }
        .control-group h3 { margin: 0 0 10px 0; font-size: 16px; }
        input[type="text"], input[type="file"] { width: 100%; padding: 8px; margin-bottom: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        button { background: #3498db; color: #fff; border: none; padding: 8px 15px; border-radius: 4px; cursor: pointer; transition: background 0.3s; }
        button:hover { background: #2980b9; }
        .btn-danger { background: #e74c3c; }
        .btn-danger:hover { background: #c0392b; }
        .btn-warning { background: #f1c40f; color: #333; }
        .btn-warning:hover { background: #f39c12; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; }
        tr:hover { background: #f1f4f6; }
        .icon { margin-right: 8px; font-size: 18px; }
        a.item-link { text-decoration: none; color: #2c3e50; font-weight: 500; }
        a.item-link:hover { color: #3498db; }
        .actions { display: flex; gap: 5px; }
        .actions form { margin: 0; }
        .message { padding: 10px; background: #d4edda; color: #155724; border-radius: 4px; margin-bottom: 20px; }
    </style>
</head>
<body>

<div class="container">
    <h1>File Manager</h1>

    <?php if ($message): ?>
        <div class="message"><?php echo htmlspecialchars($message); ?></div>
    <?php endif; ?>

    <div class="breadcrumb">
        <strong>Path:</strong> 
        <?php
        $parts = explode(DIRECTORY_SEPARATOR, str_replace($base_dir, '', $current_dir));
        $build_path = $base_dir;
        echo '<a href="?dir=' . urlencode($base_dir) . '">Root</a>';
        foreach ($parts as $part) {
            if ($part !== '') {
                $build_path .= DIRECTORY_SEPARATOR . $part;
                echo ' / <a href="?dir=' . urlencode($build_path) . '">' . htmlspecialchars($part) . '</a>';
            }
        }
        ?>
    </div>

    <div class="controls">
        <div class="control-group">
            <h3>Upload File</h3>
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="action" value="upload">
                <input type="file" name="file" required>
                <button type="submit">Upload</button>
            </form>
        </div>
        <div class="control-group">
            <h3>Create Directory</h3>
            <form method="POST">
                <input type="hidden" name="action" value="mkdir">
                <input type="text" name="foldername" placeholder="Directory Name" required>
                <button type="submit">Create</button>
            </form>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>Name</th>
                <th>Size</th>
                <th>Modified</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php if ($current_dir !== $base_dir): ?>
            <tr>
                <td><a href="?dir=<?php echo urlencode(dirname($current_dir)); ?>" class="item-link"><span class="icon">📁</span>..</a></td>
                <td>-</td>
                <td>-</td>
                <td>-</td>
            </tr>
            <?php endif; ?>

            <?php foreach ($directories as $dir): 
                if ($dir === '..') continue;
                $path = $current_dir . DIRECTORY_SEPARATOR . $dir;
            ?>
            <tr>
                <td><a href="?dir=<?php echo urlencode($path); ?>" class="item-link"><span class="icon">📁</span><?php echo htmlspecialchars($dir); ?></a></td>
                <td>-</td>
                <td><?php echo date("Y-m-d H:i", filemtime($path)); ?></td>
                <td class="actions">
                    <button class="btn-warning" onclick="renameItem('<?php echo addslashes($path); ?>', '<?php echo addslashes($dir); ?>')">Rename</button>
                    <form method="POST" onsubmit="return confirm('Delete directory?');">
                        <input type="hidden" name="action" value="delete">
                        <input type="hidden" name="target" value="<?php echo htmlspecialchars($path); ?>">
                        <button type="submit" class="btn-danger">Delete</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>

            <?php foreach ($files as $file): 
                $path = $current_dir . DIRECTORY_SEPARATOR . $file;
            ?>
            <tr>
                <td><span class="icon">📄</span><?php echo htmlspecialchars($file); ?></td>
                <td><?php echo formatSize(filesize($path)); ?></td>
                <td><?php echo date("Y-m-d H:i", filemtime($path)); ?></td>
                <td class="actions">
                    <a href="?download=<?php echo urlencode($path); ?>"><button>Download</button></a>
                    <button class="btn-warning" onclick="renameItem('<?php echo addslashes($path); ?>', '<?php echo addslashes($file); ?>')">Rename</button>
                    <form method="POST" onsubmit="return confirm('Delete file?');">
                        <input type="hidden" name="action" value="delete">
                        <input type="hidden" name="target" value="<?php echo htmlspecialchars($path); ?>">
                        <button type="submit" class="btn-danger">Delete</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<form id="renameForm" method="POST" style="display: none;">
    <input type="hidden" name="action" value="rename">
    <input type="hidden" name="old_name" id="renameOld">
    <input type="hidden" name="new_name" id="renameNew">
</form>

<script>
function renameItem(oldPath, currentName) {
    let newName = prompt("Enter new name:", currentName);
    if (newName !== null && newName.trim() !== "" && newName !== currentName) {
        document.getElementById('renameOld').value = oldPath;
        document.getElementById('renameNew').value = newName.trim();
        document.getElementById('renameForm').submit();
    }
}
</script>

</body>
</html>
