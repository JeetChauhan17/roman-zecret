#!/usr/bin/env python3

import curses
import os
import time
import datetime
import getpass
import hashlib
import base64
import random
import textwrap
import traceback # For debugging curses issues

# --- External Dependency ---
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Error: 'cryptography' library not found.")
    print("Please install it using: pip install cryptography")
    exit(1)
# --- End External Dependency ---

# --- Configuration ---
APP_NAME = "Roman Zecret"
NOTES_DIR = "roman_zecret_notes"
PASSWORD_FILE = ".roman_zecret_hash"
SALT_SIZE = 16
KEY_ITERATIONS = 100_000 # Adjust as needed for security/performance balance
ENTRY_EXTENSION = ".rz"

# --- Spooky UI Elements ---
SKULL_HEADER = [
    r"  _____                               ______                  _   ",
    r" |  __ \                             |___  /                 | |  ",
    r" | |__) |___  _ __ ___   __ _ _ __      / / ___  ___ _ __ ___| |_ ",
    r" |  _  // _ \| '_ ` _ \ / _` | '_ \    / / / _ \/ __| '__/ _ \ __|",
    r" | | \ \ (_) | | | | | | (_| | | | |  / /_|  __/ (__| | |  __/ |_ ",
    r" |_|  \_\___/|_| |_| |_|\__,_|_| |_| /_____\___|\___|_|  \___|\__|",
    r"                                                                  ",
    r"                                                                  ",
]

SPOOKY_EMOJIS = ["💀", "👻", "🎃", "🦇", "🕸️", "🕯️", "⚰️", "🔮", "😱", "🔪"]

# --- Color Pairs (Initialize in main) ---
COLOR_PAIR_DEFAULT = 1
COLOR_PAIR_HEADER = 2
COLOR_PAIR_MENU_ACTIVE = 3
COLOR_PAIR_MENU_INACTIVE = 4
COLOR_PAIR_INFO = 5
COLOR_PAIR_ERROR = 6
COLOR_PAIR_SUCCESS = 7
COLOR_PAIR_INPUT = 8
COLOR_PAIR_BORDER = 9

# --- Helper Functions ---

def get_key_from_password(password, salt):
    """Derives a cryptographic key from the password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # Fernet key size
        salt=salt,
        iterations=KEY_ITERATIONS,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_data(data, key):
    """Encrypts data using Fernet."""
    f = Fernet(key)
    # Prepend a title separator for easier parsing later
    # Ensure data is bytes
    if isinstance(data, str):
        data = data.encode('utf-8')
    return f.encrypt(data)

def decrypt_data(encrypted_data, key):
    """Decrypts data using Fernet. Returns None on failure."""
    f = Fernet(key)
    try:
        decrypted = f.decrypt(encrypted_data)
        return decrypted.decode('utf-8') # Return as string
    except InvalidToken:
        return None # Indicates wrong key or corrupted data
    except Exception: # Catch other potential decryption errors
        return None

def save_password_hash(password):
    """Hashes the password with a new salt and saves salt:hash."""
    salt = os.urandom(SALT_SIZE)
    key = get_key_from_password(password, salt) # Use the KDF here too
    # Store salt and a hash of the *derived key* for verification, not the raw password hash
    # This verifies the key derivation process itself
    hasher = hashlib.sha256()
    hasher.update(key)
    key_hash = hasher.hexdigest()

    try:
        with open(PASSWORD_FILE, "w") as f:
            f.write(f"{base64.b64encode(salt).decode()}:{key_hash}")
        # Set restrictive permissions (macOS/Linux)
        os.chmod(PASSWORD_FILE, 0o600)
        return salt, key # Return salt and the derived key for immediate use
    except IOError:
        return None, None

def load_password_salt_and_hash():
    """Loads salt and hash from the password file."""
    try:
        with open(PASSWORD_FILE, "r") as f:
            line = f.readline().strip()
            salt_b64, stored_key_hash = line.split(':')
            salt = base64.b64decode(salt_b64)
            return salt, stored_key_hash
    except (FileNotFoundError, ValueError, IndexError, IOError):
        return None, None

def verify_password(password, salt, stored_key_hash):
    """Verifies the entered password against the stored hash using the salt."""
    key = get_key_from_password(password, salt)
    hasher = hashlib.sha256()
    hasher.update(key)
    current_key_hash = hasher.hexdigest()
    return current_key_hash == stored_key_hash, key # Return boolean and the derived key

def get_sorted_notes():
    """Returns a sorted list of note filenames."""
    try:
        notes = [f for f in os.listdir(NOTES_DIR) if f.endswith(ENTRY_EXTENSION)]
        # Sort by filename (which includes timestamp)
        notes.sort(reverse=True) # Show newest first
        return notes
    except FileNotFoundError:
        return []

def clear_screen(stdscr):
    """Clears the terminal screen."""
    stdscr.clear()

def draw_header(stdscr, y_offset=1):
    """Draws the spooky skull header."""
    max_y, max_x = stdscr.getmaxyx()
    header_height = len(SKULL_HEADER)
    if max_y < header_height + y_offset: return # Not enough space

    for i, line in enumerate(SKULL_HEADER):
        x = max(0, (max_x - len(line)) // 2)
        safe_line = line[:max_x-1] # Prevent writing past screen edge
        try:
            stdscr.addstr(y_offset + i, x, safe_line, curses.color_pair(COLOR_PAIR_HEADER) | curses.A_BOLD)
        except curses.error:
            pass # Ignore errors if writing fails near edge

def draw_message(stdscr, message, y, color_pair, delay=0, spooky=True):
    """Displays a message at a specific row, clears it after a delay."""
    max_y, max_x = stdscr.getmaxyx()
    if y >= max_y: return

    prefix = random.choice(SPOOKY_EMOJIS) + " " if spooky else ""
    full_message = prefix + message
    x = max(0, (max_x - len(full_message)) // 2)
    
    # Ensure message fits
    if len(full_message) >= max_x:
        full_message = full_message[:max_x-1]
        x = 0

    try:
        # Clear the line first
        stdscr.move(y, 0)
        stdscr.clrtoeol()
        stdscr.attron(curses.color_pair(color_pair) | curses.A_BOLD)
        stdscr.addstr(y, x, full_message)
        stdscr.attroff(curses.color_pair(color_pair) | curses.A_BOLD)
        stdscr.refresh()
        if delay > 0:
            time.sleep(delay)
            # Clear the message line after delay
            stdscr.move(y, 0)
            stdscr.clrtoeol()
            stdscr.refresh()
    except curses.error:
        pass # Ignore potential errors writing to screen edges


def get_string_input(stdscr, y, x, prompt, max_len=50, password=False):
    """Gets string input from the user at a specific position."""
    max_y, max_x = stdscr.getmaxyx()
    if y >= max_y or x + len(prompt) + 1 >= max_x:
        return "" # Not enough space

    stdscr.attron(curses.color_pair(COLOR_PAIR_INPUT))
    stdscr.addstr(y, x, prompt)
    stdscr.attroff(curses.color_pair(COLOR_PAIR_INPUT))
    stdscr.refresh()

    curses.echo() # Enable echoing characters
    curses.curs_set(1) # Show cursor
    
    # Input window/field
    input_win_x = x + len(prompt) + 1
    input_win_width = min(max_len, max_x - input_win_x - 1)
    input_win = curses.newwin(1, input_win_width, y, input_win_x)
    input_win.bkgd(' ', curses.color_pair(COLOR_PAIR_DEFAULT)) # Background for input field

    text = ""
    input_win.keypad(True)

    while True:
        input_win.clear()
        display_text = "*" * len(text) if password else text
        # Handle scrolling display if text exceeds width
        start_display = max(0, len(display_text) - input_win_width + 1)
        input_win.addstr(0, 0, display_text[start_display:], curses.color_pair(COLOR_PAIR_INPUT))
        input_win.refresh()

        try:
            key = input_win.getch()
        except KeyboardInterrupt: # Allow Ctrl+C to exit input
            text = None # Signal cancellation
            break

        if key in [curses.KEY_ENTER, 10, 13]: # Enter key
            break
        elif key in [curses.KEY_BACKSPACE, 127, 8]: # Backspace
            if len(text) > 0:
                text = text[:-1]
        elif key == 27: # Escape key - treat as cancel
             text = None # Signal cancellation
             break
        elif 32 <= key <= 126: # Printable ASCII characters
            if len(text) < max_len:
                 text += chr(key)
        # Add more key handling if needed (arrows, etc.)

    curses.noecho() # Disable echoing
    curses.curs_set(0) # Hide cursor
    del input_win # Clean up window

    # Clear the prompt and input area
    stdscr.move(y, x)
    stdscr.clrtoeol()
    stdscr.refresh()

    return text


def get_multiline_input(stdscr, y_start, x_start, prompt):
    """Gets multi-line input (basic editor). Returns a list of lines."""
    max_y, max_x = stdscr.getmaxyx()
    lines = [""]
    current_line_idx = 0
    cursor_x = 0 # Position within the current line
    
    stdscr.attron(curses.color_pair(COLOR_PAIR_INPUT))
    stdscr.addstr(y_start, x_start, prompt)
    stdscr.addstr(y_start + 1, x_start, "(Press Ctrl+D or Ctrl+G to finish)")
    stdscr.attroff(curses.color_pair(COLOR_PAIR_INPUT))
    
    curses.curs_set(1) # Show cursor
    
    edit_win_y = y_start + 2
    edit_win_h = max_y - edit_win_y - 1 # Leave space at bottom
    edit_win_w = max_x - x_start - 2
    
    if edit_win_h <= 0 or edit_win_w <= 0:
        return None # Not enough space

    # Keep track of top line displayed for scrolling
    top_line_idx = 0 
    
    while True:
        # --- Redraw the editing area ---
        stdscr.move(edit_win_y, x_start)
        for i in range(edit_win_h):
             stdscr.clrtoeol() # Clear line before writing
             line_idx_to_draw = top_line_idx + i
             if line_idx_to_draw < len(lines):
                 # Simple wrapping for display
                 wrapped_lines = textwrap.wrap(lines[line_idx_to_draw], width=edit_win_w)
                 if not wrapped_lines: # Handle empty line case after wrap
                     wrapped_lines = [""] 
                 # Display only the relevant part if wrapped (this part is simplified)
                 # For simplicity, just show the first wrapped segment or indicate more
                 display_line = wrapped_lines[0]
                 if len(wrapped_lines) > 1:
                     display_line = display_line[:-3] + "..." # Indicate more content
                     
                 # Truncate if still too long (shouldn't happen with wrap)
                 display_line = display_line[:edit_win_w] 
                 
                 try:
                    stdscr.addstr(edit_win_y + i, x_start, display_line)
                 except curses.error:
                     pass # Ignore drawing errors at edges
             else:
                 # Clear lines below content
                 stdscr.move(edit_win_y + i, x_start)
                 stdscr.clrtoeol()
                 
        # --- Place cursor ---
        # Calculate cursor position based on current line and potential wrapping
        current_line_content = lines[current_line_idx]
        cursor_y_in_win = (current_line_idx - top_line_idx) 
        # Simplified cursor X - doesn't handle wrapping accurately
        cursor_x_in_win = cursor_x 
        
        # Clamp cursor position within window bounds
        cursor_y_in_win = max(0, min(edit_win_h - 1, cursor_y_in_win))
        cursor_x_in_win = max(0, min(edit_win_w - 1, cursor_x_in_win))

        try:
            stdscr.move(edit_win_y + cursor_y_in_win, x_start + cursor_x_in_win)
        except curses.error:
             # If cursor move fails, try moving to start of line
             try: stdscr.move(edit_win_y + cursor_y_in_win, x_start)
             except curses.error: pass # Give up if even that fails

        stdscr.refresh()
        
        # --- Get Input ---
        try:
             key = stdscr.getch()
        except KeyboardInterrupt:
             lines = None # Cancel
             break
             
        # --- Process Input ---
        current_line = lines[current_line_idx]

        if key in [curses.KEY_ENTER, 10, 13]: # Newline
            before_cursor = current_line[:cursor_x]
            after_cursor = current_line[cursor_x:]
            lines[current_line_idx] = before_cursor
            current_line_idx += 1
            lines.insert(current_line_idx, after_cursor)
            cursor_x = 0
        elif key in [curses.KEY_BACKSPACE, 127, 8]: # Backspace
            if cursor_x > 0:
                lines[current_line_idx] = current_line[:cursor_x-1] + current_line[cursor_x:]
                cursor_x -= 1
            elif current_line_idx > 0: # Backspace at start of line, merge with previous
                 prev_line = lines[current_line_idx-1]
                 cursor_x = len(prev_line) # Move cursor to end of previous line
                 lines[current_line_idx-1] = prev_line + current_line
                 del lines[current_line_idx]
                 current_line_idx -= 1
        elif key == curses.KEY_DC: # Delete key (may not work on all terminals)
             if cursor_x < len(current_line):
                 lines[current_line_idx] = current_line[:cursor_x] + current_line[cursor_x+1:]
             # Add logic here to merge with next line if at end of current line
        elif key == curses.KEY_UP:
             if current_line_idx > 0:
                 current_line_idx -= 1
                 # Try to maintain horizontal position
                 cursor_x = min(cursor_x, len(lines[current_line_idx]))
        elif key == curses.KEY_DOWN:
             if current_line_idx < len(lines) - 1:
                 current_line_idx += 1
                 # Try to maintain horizontal position
                 cursor_x = min(cursor_x, len(lines[current_line_idx]))
        elif key == curses.KEY_LEFT:
             if cursor_x > 0:
                 cursor_x -= 1
             elif current_line_idx > 0: # Move to end of previous line
                 current_line_idx -= 1
                 cursor_x = len(lines[current_line_idx])
        elif key == curses.KEY_RIGHT:
             if cursor_x < len(current_line):
                 cursor_x += 1
             elif current_line_idx < len(lines) - 1: # Move to start of next line
                 current_line_idx += 1
                 cursor_x = 0
        elif key in [4, 7]: # Ctrl+D or Ctrl+G often used for EOF/finish
             break # Finish editing
        elif 32 <= key <= 126: # Printable characters
             lines[current_line_idx] = current_line[:cursor_x] + chr(key) + current_line[cursor_x:]
             cursor_x += 1
        elif key == 27: # Check for escape sequences (like arrows, if keypad isn't working)
            # This requires more complex handling, ignore for now
            pass
            
        # --- Adjust Scroll ---
        if current_line_idx < top_line_idx:
             top_line_idx = current_line_idx
        elif current_line_idx >= top_line_idx + edit_win_h:
             top_line_idx = current_line_idx - edit_win_h + 1
             
    curses.curs_set(0) # Hide cursor
    # Clear the editing area
    for i in range(edit_win_h + 2): # Include prompt lines
        stdscr.move(y_start + i, x_start)
        stdscr.clrtoeol()
    stdscr.refresh()

    return lines


def display_menu(stdscr, menu_options, active_option):
    """Displays the main menu."""
    max_y, max_x = stdscr.getmaxyx()
    header_height = len(SKULL_HEADER)
    menu_start_y = header_height + 3 # Leave space below header

    if menu_start_y + len(menu_options) >= max_y:
         # Handle case where menu doesn't fit (basic version)
         stdscr.addstr(menu_start_y, 1, "Terminal too small!", curses.color_pair(COLOR_PAIR_ERROR))
         return

    for i, option in enumerate(menu_options):
        y = menu_start_y + i
        x = 5 # Indent menu items
        style = curses.A_NORMAL
        color_pair = COLOR_PAIR_MENU_INACTIVE
        prefix = "  "
        if i == active_option:
            style = curses.A_BOLD | curses.A_REVERSE
            color_pair = COLOR_PAIR_MENU_ACTIVE
            prefix = "-> " + random.choice(SPOOKY_EMOJIS) # Spooky indicator

        display_text = f"{prefix} {option}"[:max_x-x-1] # Truncate if needed

        try:
            stdscr.attron(curses.color_pair(color_pair) | style)
            stdscr.addstr(y, x, display_text)
            stdscr.attroff(curses.color_pair(color_pair) | style)
            # Clear rest of the line
            stdscr.addstr(y, x + len(display_text), " " * (max_x - x - len(display_text) -1))
        except curses.error:
            pass # Ignore writing errors at edges

# --- Core Application Logic ---

def write_new_entry(stdscr, encryption_key):
    """Handles writing and saving a new diary entry."""
    max_y, max_x = stdscr.getmaxyx()
    clear_screen(stdscr)
    draw_header(stdscr)
    prompt_y = len(SKULL_HEADER) + 2
    input_x = 2

    try:
        stdscr.addstr(prompt_y, input_x, "💀 Writing a New Zecret... 💀", curses.color_pair(COLOR_PAIR_INFO) | curses.A_BOLD)
        stdscr.refresh()
        
        title = get_string_input(stdscr, prompt_y + 2, input_x, "Title: ", max_len=80)
        if title is None: # User cancelled
             draw_message(stdscr, "Entry cancelled.", max_y - 2, COLOR_PAIR_INFO, delay=1.5)
             return

        if not title: title = "Untitled Zecret" # Default title

        draw_message(stdscr, "Enter content below.", prompt_y + 4, COLOR_PAIR_INFO)
        stdscr.refresh()
        time.sleep(0.5) # Dramatic pause

        content_lines = get_multiline_input(stdscr, prompt_y + 5, input_x, "Content:")
        if content_lines is None: # User cancelled
            draw_message(stdscr, "Entry cancelled.", max_y - 2, COLOR_PAIR_INFO, delay=1.5)
            return
        
        content = "\n".join(content_lines)
        
        if not content.strip():
             draw_message(stdscr, "Entry has no content. Saving cancelled.", max_y - 2, COLOR_PAIR_ERROR, delay=2)
             return

        # Combine title and content (with a separator for easy parsing on read)
        full_entry_data = f"TITLE:{title}\n--CONTENT--\n{content}"

        # --- Animation: Saving ---
        draw_message(stdscr, "Encrypting your Zecret...", max_y - 3, COLOR_PAIR_INFO, spooky=True)
        stdscr.refresh()
        time.sleep(0.8)
        # --- End Animation ---

        encrypted_content = encrypt_data(full_entry_data, encryption_key)
        if not encrypted_content:
            draw_message(stdscr, "Encryption failed! Entry not saved.", max_y - 2, COLOR_PAIR_ERROR, delay=3)
            return

        # --- Animation: Saving ---
        for i in range(3):
             draw_message(stdscr, f"Saving to the crypt{'.' * (i+1)}", max_y - 3, COLOR_PAIR_INFO, spooky=True)
             stdscr.refresh()
             time.sleep(0.4)
        # --- End Animation ---

        # Generate filename
        now = datetime.datetime.now()
        filename = now.strftime(f"%Y%m%d_%H%M%S_{random.randint(100,999)}{ENTRY_EXTENSION}")
        filepath = os.path.join(NOTES_DIR, filename)

        try:
            with open(filepath, "wb") as f:
                f.write(encrypted_content)
            draw_message(stdscr, f"Zecret '{filename}' saved! 👻", max_y - 2, COLOR_PAIR_SUCCESS, delay=2)
        except IOError as e:
            draw_message(stdscr, f"Error saving file: {e}", max_y - 2, COLOR_PAIR_ERROR, delay=3)

    except Exception as e:
        # Catch unexpected errors during the process
        draw_message(stdscr, f"An error occurred: {e}", max_y - 2, COLOR_PAIR_ERROR, delay=3)


def select_and_read_entry(stdscr, encryption_key, edit_mode=False):
    """Allows selecting a note and reads/displays it (or prepares for edit)."""
    max_y, max_x = stdscr.getmaxyx()
    notes = get_sorted_notes()

    if not notes:
        draw_message(stdscr, "No Zecrets found in the crypt! 🕸️", max_y - 2, COLOR_PAIR_INFO, delay=2)
        return None if edit_mode else False

    active_option = 0
    list_offset = 0 # For scrolling through notes

    header_height = len(SKULL_HEADER)
    list_y_start = header_height + 2
    list_height = max_y - list_y_start - 3 # Space for header, message, border

    if list_height <= 0:
         draw_message(stdscr, "Terminal too small to list notes!", max_y-2, COLOR_PAIR_ERROR, delay=2)
         return None if edit_mode else False

    action_verb = "Edit" if edit_mode else "Read"
    
    while True:
        clear_screen(stdscr)
        draw_header(stdscr)
        
        prompt = f"Select a Zecret to {action_verb} (Use ↑↓, Enter to select, Esc/Q to cancel):"
        try:
             stdscr.addstr(list_y_start, 2, prompt, curses.color_pair(COLOR_PAIR_INFO))
        except curses.error: pass

        # Draw the list portion
        for i in range(list_height):
             idx = list_offset + i
             if idx < len(notes):
                 note_name = notes[idx]
                 prefix = "  "
                 style = curses.A_NORMAL
                 color = COLOR_PAIR_MENU_INACTIVE
                 
                 if idx == active_option:
                     prefix = "->💀"
                     style = curses.A_BOLD | curses.A_REVERSE
                     color = COLOR_PAIR_MENU_ACTIVE
                 
                 display_text = f"{prefix} {note_name}"[:max_x - 4] # Truncate
                 
                 try:
                    stdscr.attron(curses.color_pair(color) | style)
                    stdscr.addstr(list_y_start + 2 + i, 3, display_text) # Start list below prompt
                    stdscr.attroff(curses.color_pair(color) | style)
                    # Clear rest of line
                    stdscr.addstr(list_y_start + 2 + i, 3 + len(display_text), " " * (max_x - 3 - len(display_text) - 1))
                 except curses.error: pass
             else:
                 # Clear line if no note to display here
                 stdscr.move(list_y_start + 2 + i, 3)
                 stdscr.clrtoeol()
                 
        # Display scroll indicators if needed
        if list_offset > 0:
            try: stdscr.addstr(list_y_start + 1, max_x - 5, "↑ More", curses.color_pair(COLOR_PAIR_INFO))
            except curses.error: pass
        if list_offset + list_height < len(notes):
             try: stdscr.addstr(list_y_start + list_height + 2, max_x - 5, "↓ More", curses.color_pair(COLOR_PAIR_INFO))
             except curses.error: pass
             
        stdscr.refresh()

        key = stdscr.getch()

        if key == curses.KEY_UP:
            if active_option > 0:
                active_option -= 1
                if active_option < list_offset:
                    list_offset = active_option # Scroll up
        elif key == curses.KEY_DOWN:
            if active_option < len(notes) - 1:
                active_option += 1
                if active_option >= list_offset + list_height:
                    list_offset += 1 # Scroll down
        elif key in [curses.KEY_ENTER, 10, 13]:
            selected_note = notes[active_option]
            filepath = os.path.join(NOTES_DIR, selected_note)
            
            # --- Animation: Decrypting ---
            draw_message(stdscr, f"Unlocking {selected_note}...", max_y - 2, COLOR_PAIR_INFO, spooky=True)
            stdscr.refresh()
            time.sleep(0.7)
            # --- End Animation ---

            try:
                with open(filepath, "rb") as f:
                    encrypted_data = f.read()
                
                decrypted_full_entry = decrypt_data(encrypted_data, encryption_key)

                if decrypted_full_entry is None:
                    draw_message(stdscr, "Decryption Failed! Wrong key or corrupt file? 😱", max_y - 2, COLOR_PAIR_ERROR, delay=3)
                    return None if edit_mode else False # Stay in loop or return appropriate value
                    
                # Parse Title and Content
                title = f"Zecret: {selected_note}" # Default if parsing fails
                content = decrypted_full_entry # Default if parsing fails
                parts = decrypted_full_entry.split("\n--CONTENT--\n", 1)
                if len(parts) == 2 and parts[0].startswith("TITLE:"):
                    title = parts[0][len("TITLE:"):].strip()
                    content = parts[1]

                if edit_mode:
                    return selected_note, title, content # Return data needed for editing
                else:
                    # Display the note
                    display_note_content(stdscr, title, content, selected_note)
                    return True # Indicate success

            except FileNotFoundError:
                draw_message(stdscr, "File not found! Maybe deleted?", max_y - 2, COLOR_PAIR_ERROR, delay=2)
                notes = get_sorted_notes() # Refresh list
                if not notes: return False
                active_option = min(active_option, len(notes)-1)
                list_offset = min(list_offset, max(0, len(notes)-list_height))

            except Exception as e:
                draw_message(stdscr, f"Error reading file: {e}", max_y - 2, COLOR_PAIR_ERROR, delay=3)
                return None if edit_mode else False

        elif key in [27, ord('q'), ord('Q')]: # Escape or Q
            return None if edit_mode else False # Cancelled

def display_note_content(stdscr, title, content, note_name):
    """Displays the decrypted content of a note."""
    max_y, max_x = stdscr.getmaxyx()
    lines = content.splitlines()
    
    display_offset = 0 # Top line index for scrolling
    
    while True:
        clear_screen(stdscr)
        draw_header(stdscr)
        
        header_y = len(SKULL_HEADER) + 2
        content_y_start = header_y + 2
        content_height = max_y - content_y_start - 2 # Space for header, title, footer

        # Display Title
        title_str = f"🦇 {title} ({note_name}) 🦇"[:max_x-4]
        title_x = max(1, (max_x - len(title_str)) // 2)
        try:
             stdscr.attron(curses.color_pair(COLOR_PAIR_HEADER) | curses.A_BOLD)
             stdscr.addstr(header_y, title_x, title_str)
             stdscr.attroff(curses.color_pair(COLOR_PAIR_HEADER) | curses.A_BOLD)
        except curses.error: pass

        if content_height <= 0:
             draw_message(stdscr, "Terminal too small to display content!", max_y-2, COLOR_PAIR_ERROR, delay=2)
             time.sleep(1)
             return

        # Display Content Lines
        for i in range(content_height):
            line_idx = display_offset + i
            if line_idx < len(lines):
                # Basic wrapping for display
                wrapped_lines = textwrap.wrap(lines[line_idx], width=max_x - 4)
                if not wrapped_lines: wrapped_lines=[""] # Handle empty lines
                
                # Only display the first part of wrapped line for simplicity
                display_line = wrapped_lines[0][:max_x-4]
                
                try:
                    stdscr.addstr(content_y_start + i, 2, display_line)
                except curses.error: pass
            else:
                # Clear lines below content
                stdscr.move(content_y_start + i, 2)
                stdscr.clrtoeol()

        # Footer Instructions
        footer_y = max_y - 1
        instructions = "Use ↑↓ or PgUp/PgDn to Scroll | Press Q or Esc to Return"
        try:
             stdscr.attron(curses.color_pair(COLOR_PAIR_INFO) | curses.A_REVERSE)
             stdscr.addstr(footer_y, 0, instructions.ljust(max_x))
             stdscr.attroff(curses.color_pair(COLOR_PAIR_INFO) | curses.A_REVERSE)
        except curses.error: pass
        
        # Scroll indicators
        if display_offset > 0:
            try: stdscr.addstr(content_y_start, max_x - 3, "↑↑", curses.color_pair(COLOR_PAIR_INFO))
            except curses.error: pass
        if display_offset + content_height < len(lines):
             try: stdscr.addstr(content_y_start + content_height - 1, max_x - 3, "↓↓", curses.color_pair(COLOR_PAIR_INFO))
             except curses.error: pass
             
        stdscr.refresh()

        key = stdscr.getch()

        if key == curses.KEY_UP:
            if display_offset > 0: display_offset -= 1
        elif key == curses.KEY_DOWN:
             # Check if there's more content to scroll down to
             if display_offset + content_height < len(lines):
                 display_offset += 1
        elif key == curses.KEY_PPAGE: # Page Up
             display_offset = max(0, display_offset - content_height)
        elif key == curses.KEY_NPAGE: # Page Down
             # Check if there's more content
             if display_offset + content_height < len(lines):
                 display_offset = min(len(lines) - content_height, display_offset + content_height)
                 display_offset = max(0, display_offset) # Ensure not negative

        elif key in [27, ord('q'), ord('Q')]: # Escape or Q
            break # Exit display


# def edit_entry(stdscr, encryption_key):
    """Handles selecting, editing, and re-saving an entry."""
    max_y, max_x = stdscr.getmaxyx()

    # Select the note first
    selection_result = select_and_read_entry(stdscr, encryption_key, edit_mode=True)

    if selection_result is None:
        # User cancelled selection or an error occurred during selection/decryption
        # Message should have been displayed by select_and_read_entry
        return

    selected_note_file, old_title, old_content = selection_result
    filepath = os.path.join(NOTES_DIR, selected_note_file)

    clear_screen(stdscr)
    draw_header(stdscr)
    prompt_y = len(SKULL_HEADER) + 2
    input_x = 2

    try:
        stdscr.addstr(prompt_y, input_x, f"💀 Editing Zecret: {selected_note_file} 💀", curses.color_pair(COLOR_PAIR_INFO) | curses.A_BOLD)
        
        # --- Offer to Edit Title ---
        stdscr.addstr(prompt_y + 2, input_x, f"Current Title: {old_title}")
        new_title = get_string_input(stdscr, prompt_y + 3, input_x, "New Title (Enter to keep current): ", max_len=80)
        
        if new_title is None: # Cancelled during title input
             draw_message(stdscr, "Edit cancelled.", max_y - 2, COLOR_PAIR_INFO, delay=1.5)
             return
        elif not new_title:
             new_title = old_title # Keep the old title
        
        # --- Edit Content ---
        draw_message(stdscr, "Loading content for editing...", prompt_y + 5, COLOR_PAIR_INFO)
        stdscr.refresh()
        time.sleep(0.5)
        
        # Pre-populate the editor with existing content
        initial_lines = old_content.splitlines()
        
        # Need to re-implement multiline input to accept initial text
        # For simplicity here, we'll just use the get_multiline_input
        # You would ideally modify get_multiline_input to take 'initial_lines'
        # and start the editing session with that text.
        
        # Simulating editing: Ask user to re-enter or clear and start new
        # A real implementation would modify get_multiline_input
        clear_screen(stdscr) # Clear screen before editor
        draw_header(stdscr)
        stdscr.addstr(prompt_y, input_x, f"Editing Content for: {new_title}", curses.color_pair(COLOR_PAIR_INFO) | curses.A_BOLD)
        
        # Display old content briefly for reference (optional)
        # display_note_content(stdscr, "Old Content (Reference)", old_content, "Read Only")
        # clear_screen(stdscr)
        # draw_header(stdscr)
        # stdscr.addstr(prompt_y, input_x, f"Editing Content for: {new_title}", curses.color_pair(COLOR_PAIR_INFO) | curses.A_BOLD)
        
        # --- Get New Content ---
        # Ideally, pass 'initial_lines' to a modified get_multiline_input
        draw_message(stdscr, "Enter new content below. Old content is NOT pre-filled in this basic version.", prompt_y + 2, COLOR_PAIR_INFO)
        stdscr.refresh()
        time.sleep(1) # Give time to read message
        
        new_content_lines = get_multiline_input(stdscr, prompt_y + 4, input_x, "New Content:")

        if new_content_lines is None: # User cancelled
            draw_message(stdscr, "Edit cancelled.", max_y - 2, COLOR_PAIR_INFO, delay=1.5)
            return

        new_content = "\n".join(new_content_lines)

        if not new_content.strip():
             draw_message(stdscr, "New content is empty. Edit cancelled.", max_y - 2, COLOR_PAIR_ERROR, delay=2)
             return

        # Combine title and content
        full_entry_data = f"TITLE:{new_title}\n--CONTENT--\n{new_content}"

        # --- Animation: Saving ---
        draw_message(stdscr, "Encrypting your updated Zecret...", max_y - 3, COLOR_PAIR_INFO, spooky=True)
        stdscr.refresh()
        time.sleep(0.8)
        # --- End Animation ---

        encrypted_content = encrypt_data(full_entry_data, encryption_key)
        if not encrypted_content:
            draw_message(stdscr, "Encryption failed! Edit not saved.", max_y - 2, COLOR_PAIR_ERROR, delay=3)
            return

        # --- Animation: Saving ---
        for i in range(3):
             draw_message(stdscr, f"Updating the crypt{'.' * (i+1)}", max_y - 3, COLOR_PAIR_INFO, spooky=True)
             stdscr.refresh()
             time.sleep(0.4)
        # --- End Animation ---

        try:
            # Overwrite the original file
            with open(filepath, "wb") as f:
                f.write(encrypted_content)
            draw_message(stdscr, f"Zecret '{selected_note_file}' updated! ✨", max_y - 2, COLOR_PAIR_SUCCESS, delay=2)
        except IOError as e:
            draw_message(stdscr, f"Error saving updated file: {e}", max_y - 2, COLOR_PAIR_ERROR, delay=3)

    except Exception as e:
        draw_message(stdscr, f"An error occurred during editing: {e}", max_y - 2, COLOR_PAIR_ERROR, delay=3)
def edit_entry(stdscr, encryption_key):
    """Handles selecting, editing, and re-saving an entry."""
    max_y, max_x = stdscr.getmaxyx()

    # Select the note first
    selection_result = select_and_read_entry(stdscr, encryption_key, edit_mode=True)

    if selection_result is None:
        # User cancelled selection or an error occurred during selection/decryption
        return

    selected_note_file, old_title, old_content = selection_result
    filepath = os.path.join(NOTES_DIR, selected_note_file)

    clear_screen(stdscr)
    draw_header(stdscr)
    prompt_y = len(SKULL_HEADER) + 2
    input_x = 2

    try:
        stdscr.addstr(prompt_y, input_x, f"💀 Editing Zecret: {selected_note_file} 💀", curses.color_pair(COLOR_PAIR_INFO) | curses.A_BOLD)
        
        # --- Offer to Edit Title ---
        stdscr.addstr(prompt_y + 2, input_x, f"Current Title: {old_title}")
        new_title = get_string_input(stdscr, prompt_y + 3, input_x, "New Title (Enter to keep current): ", max_len=80)
        
        if new_title is None: # Cancelled during title input
            draw_message(stdscr, "Edit cancelled.", max_y - 2, COLOR_PAIR_INFO, delay=1.5)
            return
        elif not new_title:
            new_title = old_title # Keep the old title
        
        # --- Choose Edit Mode ---
        edit_options = ["Overwrite (replace entire content)", "Append (add to existing content)"]
        edit_mode_choice = 0
        
        # Display edit mode options
        while True:
            for i, option in enumerate(edit_options):
                y = prompt_y + 5 + i
                style = curses.A_BOLD | curses.A_REVERSE if i == edit_mode_choice else curses.A_NORMAL
                color = COLOR_PAIR_MENU_ACTIVE if i == edit_mode_choice else COLOR_PAIR_MENU_INACTIVE
                prefix = "-> " if i == edit_mode_choice else "   "
                
                stdscr.move(y, input_x)
                stdscr.clrtoeol()
                stdscr.attron(curses.color_pair(color) | style)
                stdscr.addstr(y, input_x, f"{prefix}{option}")
                stdscr.attroff(curses.color_pair(color) | style)
            
            stdscr.refresh()
            key = stdscr.getch()
            
            if key == curses.KEY_UP and edit_mode_choice > 0:
                edit_mode_choice -= 1
            elif key == curses.KEY_DOWN and edit_mode_choice < len(edit_options) - 1:
                edit_mode_choice += 1
            elif key in [curses.KEY_ENTER, 10, 13]:
                break
            elif key == 27:  # Escape
                draw_message(stdscr, "Edit cancelled.", max_y - 2, COLOR_PAIR_INFO, delay=1.5)
                return
        
        # Clear edit mode options
        for i in range(len(edit_options)):
            stdscr.move(prompt_y + 5 + i, input_x)
            stdscr.clrtoeol()
        
        # --- Edit Content ---
        is_append_mode = (edit_mode_choice == 1)
        
        # Prepare initial content based on edit mode
        initial_content = ""
        if is_append_mode:
            initial_content = old_content + "\n\n--- APPENDED CONTENT ---\n\n"
            edit_prompt = "Append to Content:"
        else:
            initial_content = old_content
            edit_prompt = "Edit Content:"
        
        # Convert content to lines for the editor
        initial_lines = initial_content.splitlines()
        if not initial_lines:
            initial_lines = [""]  # Ensure at least one line
        
        # Create a modified version of get_multiline_input that accepts initial content
        new_content_lines = get_multiline_input_with_content(stdscr, prompt_y + 5, input_x, edit_prompt, initial_lines)

        if new_content_lines is None:  # User cancelled
            draw_message(stdscr, "Edit cancelled.", max_y - 2, COLOR_PAIR_INFO, delay=1.5)
            return

        new_content = "\n".join(new_content_lines)

        if not new_content.strip():
            draw_message(stdscr, "New content is empty. Edit cancelled.", max_y - 2, COLOR_PAIR_ERROR, delay=2)
            return

        # Combine title and content
        full_entry_data = f"TITLE:{new_title}\n--CONTENT--\n{new_content}"

        # --- Animation: Saving ---
        draw_message(stdscr, "Encrypting your updated Zecret...", max_y - 3, COLOR_PAIR_INFO, spooky=True)
        stdscr.refresh()
        time.sleep(0.8)
        # --- End Animation ---

        encrypted_content = encrypt_data(full_entry_data, encryption_key)
        if not encrypted_content:
            draw_message(stdscr, "Encryption failed! Edit not saved.", max_y - 2, COLOR_PAIR_ERROR, delay=3)
            return

        # --- Animation: Saving ---
        for i in range(3):
            draw_message(stdscr, f"Updating the crypt{'.' * (i+1)}", max_y - 3, COLOR_PAIR_INFO, spooky=True)
            stdscr.refresh()
            time.sleep(0.4)
        # --- End Animation ---

        try:
            # Overwrite the original file
            with open(filepath, "wb") as f:
                f.write(encrypted_content)
            draw_message(stdscr, f"Zecret '{selected_note_file}' updated! ✨", max_y - 2, COLOR_PAIR_SUCCESS, delay=2)
        except IOError as e:
            draw_message(stdscr, f"Error saving updated file: {e}", max_y - 2, COLOR_PAIR_ERROR, delay=3)

    except Exception as e:
        draw_message(stdscr, f"An error occurred during editing: {e}", max_y - 2, COLOR_PAIR_ERROR, delay=3)


def get_multiline_input_with_content(stdscr, y_start, x_start, prompt, initial_lines):
    """Gets multi-line input with pre-filled content. Returns a list of lines."""
    max_y, max_x = stdscr.getmaxyx()
    lines = initial_lines.copy() if initial_lines else [""]
    current_line_idx = 0
    cursor_x = 0  # Position within the current line
    
    stdscr.attron(curses.color_pair(COLOR_PAIR_INPUT))
    stdscr.addstr(y_start, x_start, prompt)
    stdscr.addstr(y_start + 1, x_start, "(Press Ctrl+D or Ctrl+G to finish)")
    stdscr.attroff(curses.color_pair(COLOR_PAIR_INPUT))
    
    curses.curs_set(1)  # Show cursor
    
    edit_win_y = y_start + 2
    edit_win_h = max_y - edit_win_y - 1  # Leave space at bottom
    edit_win_w = max_x - x_start - 2
    
    if edit_win_h <= 0 or edit_win_w <= 0:
        return None  # Not enough space

    # Keep track of top line displayed for scrolling
    top_line_idx = 0 
    
    while True:
        # --- Redraw the editing area ---
        stdscr.move(edit_win_y, x_start)
        for i in range(edit_win_h):
            stdscr.clrtoeol()  # Clear line before writing
            line_idx_to_draw = top_line_idx + i
            if line_idx_to_draw < len(lines):
                # Simple wrapping for display
                wrapped_lines = textwrap.wrap(lines[line_idx_to_draw], width=edit_win_w)
                if not wrapped_lines:  # Handle empty line case after wrap
                    wrapped_lines = [""] 
                # Display only the relevant part if wrapped (this part is simplified)
                # For simplicity, just show the first wrapped segment or indicate more
                display_line = wrapped_lines[0]
                if len(wrapped_lines) > 1:
                    display_line = display_line[:-3] + "..."  # Indicate more content
                     
                # Truncate if still too long (shouldn't happen with wrap)
                display_line = display_line[:edit_win_w] 
                 
                try:
                    stdscr.addstr(edit_win_y + i, x_start, display_line)
                except curses.error:
                    pass  # Ignore drawing errors at edges
            else:
                # Clear lines below content
                stdscr.move(edit_win_y + i, x_start)
                stdscr.clrtoeol()
                 
        # --- Place cursor ---
        # Calculate cursor position based on current line and potential wrapping
        current_line_content = lines[current_line_idx]
        cursor_y_in_win = (current_line_idx - top_line_idx) 
        # Simplified cursor X - doesn't handle wrapping accurately
        cursor_x_in_win = cursor_x 
        
        # Clamp cursor position within window bounds
        cursor_y_in_win = max(0, min(edit_win_h - 1, cursor_y_in_win))
        cursor_x_in_win = max(0, min(edit_win_w - 1, cursor_x_in_win))

        try:
            stdscr.move(edit_win_y + cursor_y_in_win, x_start + cursor_x_in_win)
        except curses.error:
            # If cursor move fails, try moving to start of line
            try: 
                stdscr.move(edit_win_y + cursor_y_in_win, x_start)
            except curses.error: 
                pass  # Give up if even that fails

        stdscr.refresh()
        
        # --- Get Input ---
        try:
            key = stdscr.getch()
        except KeyboardInterrupt:
            lines = None  # Cancel
            break
             
        # --- Process Input ---
        current_line = lines[current_line_idx]

        if key in [curses.KEY_ENTER, 10, 13]:  # Newline
            before_cursor = current_line[:cursor_x]
            after_cursor = current_line[cursor_x:]
            lines[current_line_idx] = before_cursor
            current_line_idx += 1
            lines.insert(current_line_idx, after_cursor)
            cursor_x = 0
        elif key in [curses.KEY_BACKSPACE, 127, 8]:  # Backspace
            if cursor_x > 0:
                lines[current_line_idx] = current_line[:cursor_x-1] + current_line[cursor_x:]
                cursor_x -= 1
            elif current_line_idx > 0:  # Backspace at start of line, merge with previous
                prev_line = lines[current_line_idx-1]
                cursor_x = len(prev_line)  # Move cursor to end of previous line
                lines[current_line_idx-1] = prev_line + current_line
                del lines[current_line_idx]
                current_line_idx -= 1
        elif key == curses.KEY_DC:  # Delete key (may not work on all terminals)
            if cursor_x < len(current_line):
                lines[current_line_idx] = current_line[:cursor_x] + current_line[cursor_x+1:]
            # Add logic here to merge with next line if at end of current line
        elif key == curses.KEY_UP:
            if current_line_idx > 0:
                current_line_idx -= 1
                # Try to maintain horizontal position
                cursor_x = min(cursor_x, len(lines[current_line_idx]))
        elif key == curses.KEY_DOWN:
            if current_line_idx < len(lines) - 1:
                current_line_idx += 1
                # Try to maintain horizontal position
                cursor_x = min(cursor_x, len(lines[current_line_idx]))
        elif key == curses.KEY_LEFT:
            if cursor_x > 0:
                cursor_x -= 1
            elif current_line_idx > 0:  # Move to end of previous line
                current_line_idx -= 1
                cursor_x = len(lines[current_line_idx])
        elif key == curses.KEY_RIGHT:
            if cursor_x < len(current_line):
                cursor_x += 1
            elif current_line_idx < len(lines) - 1:  # Move to start of next line
                current_line_idx += 1
                cursor_x = 0
        elif key in [4, 7]:  # Ctrl+D or Ctrl+G often used for EOF/finish
            break  # Finish editing
        elif 32 <= key <= 126:  # Printable characters
            lines[current_line_idx] = current_line[:cursor_x] + chr(key) + current_line[cursor_x:]
            cursor_x += 1
        elif key == 27:  # Check for escape sequences (like arrows, if keypad isn't working)
            # This requires more complex handling, ignore for now
            pass
            
        # --- Adjust Scroll ---
        if current_line_idx < top_line_idx:
            top_line_idx = current_line_idx
        elif current_line_idx >= top_line_idx + edit_win_h:
            top_line_idx = current_line_idx - edit_win_h + 1
             
    curses.curs_set(0)  # Hide cursor
    # Clear the editing area
    for i in range(edit_win_h + 2):  # Include prompt lines
        stdscr.move(y_start + i, x_start)
        stdscr.clrtoeol()
    stdscr.refresh()

    return lines

def import_entry(stdscr, encryption_key):
    """Imports an existing encrypted .rz file (assuming current key)."""
    max_y, max_x = stdscr.getmaxyx()
    clear_screen(stdscr)
    draw_header(stdscr)
    prompt_y = len(SKULL_HEADER) + 2
    input_x = 2

    try:
        stdscr.addstr(prompt_y, input_x, "🔮 Import Encrypted Zecret (.rz file) 🔮", curses.color_pair(COLOR_PAIR_INFO) | curses.A_BOLD)
        stdscr.refresh()

        import_path = get_string_input(stdscr, prompt_y + 2, input_x, "Path to .rz file: ", max_len=200)

        if import_path is None or not import_path.strip():
            draw_message(stdscr, "Import cancelled.", max_y - 2, COLOR_PAIR_INFO, delay=1.5)
            return

        import_path = os.path.expanduser(import_path) # Handle ~ for home directory

        if not os.path.isfile(import_path):
            draw_message(stdscr, "File not found at that path.", max_y - 2, COLOR_PAIR_ERROR, delay=2)
            return

        if not import_path.lower().endswith(ENTRY_EXTENSION):
             draw_message(stdscr, f"File must have the {ENTRY_EXTENSION} extension.", max_y - 2, COLOR_PAIR_ERROR, delay=2)
             return

        # --- Animation: Importing ---
        draw_message(stdscr, f"Attempting to read {os.path.basename(import_path)}...", max_y - 3, COLOR_PAIR_INFO, spooky=True)
        stdscr.refresh()
        time.sleep(1.0)
        # --- End Animation ---

        try:
            with open(import_path, "rb") as f:
                encrypted_data = f.read()

            # Try decrypting with the *current* key to validate
            decrypted_check = decrypt_data(encrypted_data, encryption_key)

            if decrypted_check is None:
                 draw_message(stdscr, "Decryption failed! File might be corrupt or encrypted with a different password.", max_y - 2, COLOR_PAIR_ERROR, delay=3.5)
                 return

            # --- Animation: Copying ---
            draw_message(stdscr, "Zecret unlocked! Copying to crypt...", max_y - 3, COLOR_PAIR_INFO, spooky=True)
            stdscr.refresh()
            time.sleep(1.0)
            # --- End Animation ---

            # Create a unique name in the destination directory
            base_name = os.path.basename(import_path)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            # Ensure filename doesn't clash if imported multiple times
            dest_filename = f"imported_{timestamp}_{base_name}" 
             # Ensure it still ends with .rz
            if not dest_filename.lower().endswith(ENTRY_EXTENSION):
                dest_filename += ENTRY_EXTENSION
                
            dest_path = os.path.join(NOTES_DIR, dest_filename)
            
            # Avoid overwriting existing files silently
            counter = 1
            while os.path.exists(dest_path):
                 dest_filename = f"imported_{timestamp}_{counter}_{base_name}"
                 if not dest_filename.lower().endswith(ENTRY_EXTENSION):
                     dest_filename += ENTRY_EXTENSION
                 dest_path = os.path.join(NOTES_DIR, dest_filename)
                 counter += 1
                 if counter > 100: # Safety break
                      draw_message(stdscr, "Failed to find unique name for import.", max_y-2, COLOR_PAIR_ERROR, delay=2)
                      return


            # Copy the already read encrypted data
            with open(dest_path, "wb") as f:
                 f.write(encrypted_data)

            draw_message(stdscr, f"Zecret imported as '{dest_filename}'! ✅", max_y - 2, COLOR_PAIR_SUCCESS, delay=2.5)

        except IOError as e:
            draw_message(stdscr, f"Error reading/writing file: {e}", max_y - 2, COLOR_PAIR_ERROR, delay=3)
        except Exception as e:
             draw_message(stdscr, f"An unexpected error occurred during import: {e}", max_y - 2, COLOR_PAIR_ERROR, delay=3)


    except Exception as e:
        draw_message(stdscr, f"An error occurred: {e}", max_y - 2, COLOR_PAIR_ERROR, delay=3)


def change_password(stdscr, old_key):
    """Handles changing the master password and re-encrypting notes."""
    max_y, max_x = stdscr.getmaxyx()
    clear_screen(stdscr)
    draw_header(stdscr)
    prompt_y = len(SKULL_HEADER) + 2
    input_x = 2

    stdscr.addstr(prompt_y, input_x, "🔑 Change Master Password 🔑", curses.color_pair(COLOR_PAIR_INFO) | curses.A_BOLD)
    stdscr.addstr(prompt_y + 1, input_x, "WARNING: This requires re-encrypting ALL notes!", curses.color_pair(COLOR_PAIR_ERROR))
    stdscr.refresh()

    # 1. Get and Verify Old Password
    verified = False
    for attempt in range(3):
         old_password = get_string_input(stdscr, prompt_y + 3 + attempt, input_x, f"Enter OLD Password (Attempt {attempt+1}/3): ", password=True)
         if old_password is None: # Cancelled
             draw_message(stdscr, "Password change cancelled.", max_y - 2, COLOR_PAIR_INFO, delay=1.5)
             return False, old_key # Return indicator + old key

         salt, stored_hash = load_password_salt_and_hash()
         if not salt: # Should not happen if already authenticated, but check
             draw_message(stdscr, "Error loading password data.", max_y - 2, COLOR_PAIR_ERROR, delay=2)
             return False, old_key

         verified, derived_key = verify_password(old_password, salt, stored_hash)
         if verified:
             # Important: ensure derived_key matches the currently used old_key
             if derived_key != old_key:
                 # This indicates a serious inconsistency
                  draw_message(stdscr, "CRITICAL ERROR: Key mismatch!", max_y - 2, COLOR_PAIR_ERROR, delay=4)
                  return False, old_key
             break # Verified successfully
         else:
             draw_message(stdscr, "Incorrect old password.", prompt_y + 4 + attempt, COLOR_PAIR_ERROR, delay=1)
             if attempt == 2:
                 draw_message(stdscr, "Too many failed attempts. Password change cancelled.", max_y - 2, COLOR_PAIR_ERROR, delay=2.5)
                 return False, old_key # Failed verification

    if not verified: # Should be caught above, but double check
         return False, old_key

    # Clear password prompts
    for i in range(4):
        stdscr.move(prompt_y + 3 + i, 0)
        stdscr.clrtoeol()
    stdscr.refresh()

    # 2. Get New Password
    new_password = None
    while True:
        pass1 = get_string_input(stdscr, prompt_y + 3, input_x, "Enter NEW Password: ", password=True)
        if pass1 is None:
            draw_message(stdscr, "Password change cancelled.", max_y - 2, COLOR_PAIR_INFO, delay=1.5)
            return False, old_key

        if len(pass1) < 8: # Basic check
            draw_message(stdscr, "Password too short (minimum 8 characters).", prompt_y + 5, COLOR_PAIR_ERROR, delay=2)
            stdscr.move(prompt_y+3, 0); stdscr.clrtoeol() # Clear first prompt line
            stdscr.refresh()
            continue

        pass2 = get_string_input(stdscr, prompt_y + 4, input_x, "Confirm NEW Password: ", password=True)
        if pass2 is None:
            draw_message(stdscr, "Password change cancelled.", max_y - 2, COLOR_PAIR_INFO, delay=1.5)
            return False, old_key

        if pass1 == pass2:
            new_password = pass1
            break
        else:
            draw_message(stdscr, "Passwords do not match. Try again.", prompt_y + 5, COLOR_PAIR_ERROR, delay=2)
            # Clear password prompt lines before retry
            stdscr.move(prompt_y+3, 0); stdscr.clrtoeol()
            stdscr.move(prompt_y+4, 0); stdscr.clrtoeol()
            stdscr.refresh()

    # Clear password prompts
    for i in range(3):
        stdscr.move(prompt_y + 3 + i, 0)
        stdscr.clrtoeol()
    stdscr.refresh()

    # --- Animation: Processing ---
    draw_message(stdscr, "Generating new encryption key...", max_y - 4, COLOR_PAIR_INFO, spooky=True)
    stdscr.refresh()
    time.sleep(0.8)
    # --- End Animation ---

    # 3. Save New Password Hash
    new_salt, new_key = save_password_hash(new_password)
    if not new_salt or not new_key:
        draw_message(stdscr, "ERROR: Failed to save new password hash!", max_y - 2, COLOR_PAIR_ERROR, delay=3)
        # CRITICAL: Password file might be in an inconsistent state.
        # Ideally, should backup old hash before attempting to save new one.
        return False, old_key # Return old key as change failed

    # --- Animation: Re-encrypting ---
    notes = get_sorted_notes()
    total_notes = len(notes)
    draw_message(stdscr, f"Re-encrypting {total_notes} notes with new key. This may take time...", max_y - 4, COLOR_PAIR_INFO, spooky=True)
    stdscr.refresh()
    time.sleep(1)
    # --- End Animation ---

    # 4. Re-encrypt all notes
    success_count = 0
    fail_count = 0
    status_y = max_y - 3

    for i, note_file in enumerate(notes):
        filepath = os.path.join(NOTES_DIR, note_file)
        
        # Update status
        status_msg = f"Processing: {note_file} ({i+1}/{total_notes})"
        stdscr.move(status_y, 0)
        stdscr.clrtoeol()
        try:
            stdscr.addstr(status_y, 2, status_msg[:max_x-3], curses.color_pair(COLOR_PAIR_INFO))
        except curses.error: pass
        stdscr.refresh()

        try:
            # a. Read encrypted data
            with open(filepath, "rb") as f:
                encrypted_data = f.read()
            
            # b. Decrypt with OLD key
            decrypted_content = decrypt_data(encrypted_data, old_key)
            if decrypted_content is None:
                # Skip this file, count as failure
                fail_count += 1
                # Log this? Display later?
                continue # Move to next file

            # c. Encrypt with NEW key
            new_encrypted_data = encrypt_data(decrypted_content, new_key)
            if new_encrypted_data is None:
                fail_count += 1
                continue # Move to next file

            # d. Overwrite file with newly encrypted data
            with open(filepath, "wb") as f:
                f.write(new_encrypted_data)
            
            success_count += 1
            # Optional small delay to show progress
            # time.sleep(0.05) 

        except Exception as e:
            # Log error for this specific file
            fail_count += 1
            # Maybe log 'e' somewhere
            continue # Move to next file

    # Final status message
    clear_screen(stdscr)
    draw_header(stdscr)
    final_y = len(SKULL_HEADER) + 3
    
    if fail_count == 0:
         draw_message(stdscr, f"Password changed successfully! {success_count} notes re-encrypted. ✨", final_y, COLOR_PAIR_SUCCESS, delay=3)
         return True, new_key # Success, return new key
    else:
         msg = f"Password changed, but {fail_count} out of {total_notes} notes FAILED to re-encrypt. 😥"
         msg2= "These notes may be unreadable or still use the OLD password."
         draw_message(stdscr, msg, final_y, COLOR_PAIR_ERROR, delay=0) # No clear delay
         draw_message(stdscr, msg2, final_y + 1, COLOR_PAIR_ERROR, delay=5, spooky=False)
         return True, new_key # Password hash changed, but notes are mixed. Return new key.


# --- Main Application Function ---

def main(stdscr):
    # --- Curses Initialization ---
    curses.curs_set(0) # Hide cursor
    stdscr.keypad(True) # Enable keypad mode (arrows, etc.)
    curses.start_color()
    curses.use_default_colors() # Allow using terminal default background

    # Define Color Pairs (Ensure colors are supported by terminal)
    # Using basic standard colors for better compatibility
    #            ID                FG              BG
    curses.init_pair(COLOR_PAIR_DEFAULT, curses.COLOR_WHITE, -1) # Use default background
    curses.init_pair(COLOR_PAIR_HEADER, curses.COLOR_RED, -1)
    curses.init_pair(COLOR_PAIR_MENU_ACTIVE, curses.COLOR_BLACK, curses.COLOR_GREEN) # Highlight
    curses.init_pair(COLOR_PAIR_MENU_INACTIVE, curses.COLOR_CYAN, -1)
    curses.init_pair(COLOR_PAIR_INFO, curses.COLOR_YELLOW, -1)
    curses.init_pair(COLOR_PAIR_ERROR, curses.COLOR_WHITE, curses.COLOR_RED)
    curses.init_pair(COLOR_PAIR_SUCCESS, curses.COLOR_GREEN, -1)
    curses.init_pair(COLOR_PAIR_INPUT, curses.COLOR_WHITE, -1)
    curses.init_pair(COLOR_PAIR_BORDER, curses.COLOR_MAGENTA, -1) # Example for potential borders

    stdscr.bkgd(' ', curses.color_pair(COLOR_PAIR_DEFAULT)) # Set default background/foreground

    # --- Initial Setup ---
    if not os.path.exists(NOTES_DIR):
        try:
            os.makedirs(NOTES_DIR)
            # Optional: Display a message about creating the directory
        except OSError as e:
            # Handle error if directory creation fails (e.g., permissions)
             curses.endwin()
             print(f"Error: Could not create notes directory '{NOTES_DIR}': {e}")
             exit(1)

    # --- Password Handling ---
    encryption_key = None
    salt, stored_hash = load_password_salt_and_hash()

    if not salt or not stored_hash:
        # First time setup or missing password file
        clear_screen(stdscr)
        draw_header(stdscr)
        max_y, max_x = stdscr.getmaxyx()
        setup_y = len(SKULL_HEADER) + 3
        try:
            stdscr.addstr(setup_y, 2, "Welcome to Roman Zecret! 🕯️", curses.color_pair(COLOR_PAIR_INFO))
            stdscr.addstr(setup_y + 1, 2, "Looks like it's your first time or the password file is missing.", curses.color_pair(COLOR_PAIR_INFO))
            stdscr.addstr(setup_y + 2, 2, "Let's set up your master password.", curses.color_pair(COLOR_PAIR_INFO))
            stdscr.refresh()
        except curses.error: pass

        new_password = None
        while True:
            pass1 = get_string_input(stdscr, setup_y + 4, 2, "Enter New Master Password: ", password=True)
            if pass1 is None: # User likely cancelled with Esc
                 curses.endwin()
                 print("Setup cancelled.")
                 exit(0)

            if len(pass1) < 8:
                 draw_message(stdscr, "Password too short (minimum 8 characters).", setup_y + 6, COLOR_PAIR_ERROR, delay=2)
                 # Clear prompt lines
                 stdscr.move(setup_y+4, 0); stdscr.clrtoeol()
                 stdscr.move(setup_y+5, 0); stdscr.clrtoeol()
                 stdscr.refresh()
                 continue

            pass2 = get_string_input(stdscr, setup_y + 5, 2, "Confirm Master Password: ", password=True)
            if pass2 is None:
                 curses.endwin()
                 print("Setup cancelled.")
                 exit(0)

            if pass1 == pass2:
                new_password = pass1
                break
            else:
                draw_message(stdscr, "Passwords do not match. Try again.", setup_y + 6, COLOR_PAIR_ERROR, delay=2)
                 # Clear prompt lines
                stdscr.move(setup_y+4, 0); stdscr.clrtoeol()
                stdscr.move(setup_y+5, 0); stdscr.clrtoeol()
                stdscr.refresh()

        salt, encryption_key = save_password_hash(new_password)
        if not salt or not encryption_key:
             curses.endwin()
             print("CRITICAL ERROR: Failed to save password hash during setup.")
             exit(1)
        draw_message(stdscr, "Password set successfully! Entering the crypt...", max_y - 2, COLOR_PAIR_SUCCESS, delay=2)

    else:
        # Authenticate existing user
        authenticated = False
        clear_screen(stdscr)
        draw_header(stdscr)
        max_y, max_x = stdscr.getmaxyx()
        auth_y = len(SKULL_HEADER) + 3
        try:
             stdscr.addstr(auth_y, 2, "🕯️ Enter the Crypt... Password Required 🕯️", curses.color_pair(COLOR_PAIR_INFO))
             stdscr.refresh()
        except curses.error: pass

        for attempt in range(3):
            password = get_string_input(stdscr, auth_y + 2 + attempt, 2, f"Password (Attempt {attempt+1}/3): ", password=True)
            if password is None: # Cancelled
                 curses.endwin()
                 print("\nAuthentication cancelled.")
                 exit(0)

            verified, derived_key = verify_password(password, salt, stored_hash)
            if verified:
                encryption_key = derived_key
                authenticated = True
                draw_message(stdscr, "Access Granted! Welcome back... 👻", max_y - 2, COLOR_PAIR_SUCCESS, delay=1.5)
                break
            else:
                draw_message(stdscr, "Incorrect Password! Access Denied.", auth_y + 3 + attempt, COLOR_PAIR_ERROR, delay=1)

        if not authenticated:
            curses.endwin()
            print("\nToo many failed attempts. The crypt remains sealed.")
            exit(1)


    # --- Main Menu Loop ---
    menu_options = [
        "Write New Zecret",
        "Read a Zecret",
        "Edit a Zecret",
        "Import Encrypted Zecret",
        "Change Master Password",
        "Exit Roman Zecret"
    ]
    active_option = 0

    while True:
        clear_screen(stdscr)
        draw_header(stdscr)
        display_menu(stdscr, menu_options, active_option)
        stdscr.refresh()

        key = stdscr.getch() # Wait for user input

        if key == curses.KEY_UP:
            active_option = (active_option - 1) % len(menu_options)
        elif key == curses.KEY_DOWN:
            active_option = (active_option + 1) % len(menu_options)
        elif key in [curses.KEY_ENTER, 10, 13]:
            selected_action = menu_options[active_option]

            # --- Perform Action ---
            if selected_action == "Write New Zecret":
                write_new_entry(stdscr, encryption_key)
            elif selected_action == "Read a Zecret":
                select_and_read_entry(stdscr, encryption_key, edit_mode=False)
            elif selected_action == "Edit a Zecret":
                edit_entry(stdscr, encryption_key)
            elif selected_action == "Import Encrypted Zecret":
                import_entry(stdscr, encryption_key)
            elif selected_action == "Change Master Password":
                password_changed, new_key = change_password(stdscr, encryption_key)
                if password_changed:
                    encryption_key = new_key # Update the key in use
            elif selected_action == "Exit Roman Zecret":
                 draw_message(stdscr, "Leaving the darkness... Farewell 💀", stdscr.getmaxyx()[0] - 2, COLOR_PAIR_INFO, delay=2, spooky=False)
                 break # Exit the main loop
            
            # After an action, pause briefly before showing menu again
            # unless the action itself handled delays/messages
            # time.sleep(0.5) # Optional pause

        elif key in [27, ord('q'), ord('Q')]: # Allow Esc or Q to exit directly from menu
            draw_message(stdscr, "Leaving the darkness... Farewell 💀", stdscr.getmaxyx()[0] - 2, COLOR_PAIR_INFO, delay=2, spooky=False)
            break

# --- Wrapper for Curses ---
def run_app():
    try:
        # Initialize curses
        curses.wrapper(main)
    except curses.error as e:
         # Catch curses errors if wrapper fails or during rare init issues
         print(f"A Curses error occurred: {e}")
         print("Your terminal might not fully support Curses features.")
         # Print traceback for debugging complex Curses issues
         # traceback.print_exc() 
    except Exception as e:
         # Catch any other unexpected errors
         print("\nAn unexpected error occurred:")
         traceback.print_exc()
    finally:
         # Ensure terminal is restored even if errors occurred outside wrapper scope
         # (though wrapper usually handles this)
         try:
             curses.endwin()
         except:
             pass # Ignore errors during cleanup


if __name__ == "__main__":
    run_app()