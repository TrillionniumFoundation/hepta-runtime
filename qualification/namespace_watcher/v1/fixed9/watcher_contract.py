"""Pure private native Watcher constants, without dynamic loading."""
CONTEXT_BYTES=131072
FUNCTIONS=("inotify_init1","read","fstat","fcntl","inotify_add_watch","inotify_rm_watch","close","__errno_location")
