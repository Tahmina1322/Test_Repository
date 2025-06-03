<?php
require_once 'header.php';
require_once 'functions.php';

if ($_SESSION['role'] === 'user') {
  header('Location: dashboard.php');
  exit;
}

$genres = getGenres();
$notification = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  if (!isset($_POST['csrf_token']) || !validateCsrfToken($_POST['csrf_token'])) {
    $error = 'Invalid CSRF token';
  } else {
    if (isset($_POST['add_genre'])) {
      $genreName = filter_input(INPUT_POST, 'genreName', FILTER_SANITIZE_STRING);
      $description = filter_input(INPUT_POST, 'description', FILTER_SANITIZE_STRING);
      if ($genreName && $description) {
        if (addGenre($genreName, $description, $_SESSION['userID'])) {
          $notification = "Genre '$genreName' added successfully!";
          addNotification($_SESSION['userID'], 'staff', $notification);
          header('Location: manage_genres.php?notification=' . urlencode($notification));
          exit;
        } else {
          $error = 'Failed to add genre';
        }
      } else {
        $error = 'All fields are required';
      }
    } elseif (isset($_POST['update_genre'])) {
      $genreID = filter_input(INPUT_POST, 'genreID', FILTER_SANITIZE_NUMBER_INT);
      $genreName = filter_input(INPUT_POST, 'genreName', FILTER_SANITIZE_STRING);
      $description = filter_input(INPUT_POST, 'description', FILTER_SANITIZE_STRING);
      if ($genreID && $genreName && $description) {
        if (updateGenre($genreID, $genreName, $description)) {
          $notification = "Genre '$genreName' updated successfully!";
          addNotification($_SESSION['userID'], 'staff', $notification);
          header('Location: manage_genres.php?notification=' . urlencode($notification));
          exit;
        } else {
          $error = 'Failed to update genre';
        }
      } else {
        $error = 'All fields are required';
      }
    } elseif (isset($_POST['delete_genre'])) {
      $genreID = filter_input(INPUT_POST, 'genreID', FILTER_SANITIZE_NUMBER_INT);
      if ($genreID) {
        if (deleteGenre($genreID)) {
          $notification = 'Genre deleted successfully!';
          addNotification($_SESSION['userID'], 'staff', $notification);
          header('Location: manage_genres.php?notification=' . urlencode($notification));
          exit;
        } else {
          $error = 'Cannot delete genre with associated books';
        }
      } else {
        $error = 'Invalid genre ID';
      }
    }
  }
}

$notification = filter_input(INPUT_GET, 'notification', FILTER_SANITIZE_STRING) ?? $notification;
$csrfToken = generateCsrfToken();
?>
<h2 class="text-3xl font-bold mb-6 text-indigo-700">Manage Genres</h2>
<!-- Breadcrumbs -->
<nav class="mb-4">
  <ol class="flex space-x-2 text-gray-600">
    <li><a href="dashboard.php" class="text-indigo-600 hover:text-indigo-800">Home</a></li>
    <li>/</li>
    <li>Manage Genres</li>
  </ol>
</nav>
<?php if ($notification): ?>
  <div id="notification" class="mb-4 p-3 bg-green-100 text-green-700 rounded-lg flex justify-between items-center fade-out">
    <span><?php echo htmlspecialchars($notification); ?></span>
    <button onclick="document.getElementById('notification').remove()" class="text-green-700 hover:text-green-900">✕</button>
  </div>
<?php endif; ?>
<?php if (isset($error)): ?>
  <div class="mb-4 p-3 bg-red-100 text-red-700 rounded-lg"><?php echo htmlspecialchars($error); ?></div>
<?php endif; ?>
<div class="mb-6 bg-white p-6 rounded-lg shadow-lg">
  <h3 class="text-xl font-bold mb-4 text-indigo-700">Add New Genre</h3>
  <form method="POST" class="grid grid-cols-1 md:grid-cols-2 gap-4">
    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
    <div>
      <label class="block text-gray-700 mb-1">Genre Name</label>
      <input type="text" name="genreName" class="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-indigo-500" required>
    </div>
    <div>
      <label class="block text-gray-700 mb-1">Description</label>
      <input type="text" name="description" class="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-indigo-500" required>
    </div>
    <div class="md:col-span-2">
      <button type="submit" name="add_genre" class="w-full md:w-auto bg-indigo-600 text-white p-2 rounded hover:bg-indigo-700 transition">Add Genre</button>
    </div>
  </form>
</div>

<div class="bg-white p-6 rounded-lg shadow-lg">
  <h3 class="text-xl font-bold mb-4 text-indigo-700">Existing Genres</h3>
  <?php if (empty($genres)): ?>
    <p class="text-gray-600">No genres found.</p>
  <?php else: ?>
    <div class="overflow-x-auto">
      <table class="w-full table-auto">
        <thead>
          <tr class="bg-indigo-100">
            <th class="p-2 text-left">Name</th>
            <th class="p-2 text-left">Description</th>
            <th class="p-2 text-left">Books</th>
            <th class="p-2 text-left">Actions</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach ($genres as $genre): ?>
            <tr class="border-b">
              <td class="p-2"><?php echo htmlspecialchars($genre['genreName']); ?></td>
              <td class="p-2"><?php echo htmlspecialchars($genre['description']); ?></td>
              <td class="p-2"><?php echo $genre['bookCount']; ?></td>
              <td class="p-2">
                <a href="manage_genres.php?edit=<?php echo $genre['genreID']; ?>" class="text-indigo-600 hover:text-indigo-800 mr-2">Edit</a>
                <form method="POST" class="inline" onsubmit="return confirm('Are you sure you want to delete <?php echo htmlspecialchars($genre['genreName']); ?>?')">
                  <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                  <input type="hidden" name="genreID" value="<?php echo $genre['genreID']; ?>">
                  <button type="submit" name="delete_genre" class="text-red-600 hover:text-red-800">Delete</button>
                </form>
              </td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  <?php endif; ?>
  <?php if (isset($_GET['edit'])): ?>
    <?php
    $editGenreID = filter_input(INPUT_GET, 'edit', FILTER_SANITIZE_NUMBER_INT);
    $editGenre = array_filter($genres, fn($g) => $g['genreID'] == $editGenreID);
    $editGenre = reset($editGenre);
    if ($editGenre):
    ?>
      <div class="mt-6">
        <h3 class="text-xl font-bold mb-4 text-indigo-700">Edit Genre</h3>
        <form method="POST" class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
          <input type="hidden" name="genreID" value="<?php echo $editGenre['genreID']; ?>">
          <div>
            <label class="block text-gray-700 mb-1">Genre Name</label>
            <input type="text" name="genreName" value="<?php echo htmlspecialchars($editGenre['genreName']); ?>" class="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-indigo-500" required>
          </div>
          <div>
            <label class="block text-gray-700 mb-1">Description</label>
            <input type="text" name="description" value="<?php echo htmlspecialchars($editGenre['description']); ?>" class="w-full p-2 border rounded focus:outline-none focus:ring-2 focus:ring-indigo-500" required>
          </div>
          <div class="md:col-span-2 flex space-x-2">
            <button type="submit" name="update_genre" class="bg-indigo-600 text-white p-2 rounded hover:bg-indigo-700 transition">Update Genre</button>
            <a href="manage_genres.php" class="bg-gray-300 text-gray-700 p-2 rounded hover:bg-gray-400 transition">Cancel</a>
          </div>
        </form>
      </div>
    <?php endif; ?>
  <?php endif; ?>
</div>
</div>
<?php require_once 'footer.php'; ?>
</body>
</html>