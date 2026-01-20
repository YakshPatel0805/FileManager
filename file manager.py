# # Static Program runs on local system only...

import os
import shutil

def organize_files(main_folder):
    # Define folder mapping for file extensions
    extension_folders = {
        '.gif': 'Images',
        '.jpeg': 'Images',
        '.jpg': 'Images',
        '.png': 'Images',
        '.webp': 'Images',
        '.mp4': 'Video',
        '.zip': 'Compressed',
        '.mp3': 'Music',
        '.pdf': 'Documents',
        '.xlsx': 'Documents',
        '.csv': 'Documents',
        '.py': 'Programs',
        '.exe': 'Programs',
        '.ini': 'System Files',
        '.icc': 'System Files',
    }

    # Ensure all folder names are lowercase for consistency
    existing_folders = [folder.lower() for folder in os.listdir(main_folder) if os.path.isdir(os.path.join(main_folder, folder))]

    for item in os.listdir(main_folder):
        item_path = os.path.join(main_folder, item)
        if os.path.isfile(item_path):
            _, ext = os.path.splitext(item)

            if ext in extension_folders:
                # Determine target folder name
                target_folder = extension_folders[ext]

                # Check if folder already exists (case insensitive)
                if target_folder.lower() not in existing_folders:
                    # Create new folder if not already present
                    os.makedirs(os.path.join(main_folder, target_folder), exist_ok=True)
                    existing_folders.append(target_folder.lower()) 

                # Move file to the appropriate folder
                shutil.move(item_path, os.path.join(main_folder, target_folder, item))
                print(f"Moved: {item} -> {target_folder}")
            else:
                print(f"Skipping: {item} (No folder mapping)")

# Replace this with the path to your messy folder
main_folder_path = r"add folder location"  # Update this to your folder

organize_files(main_folder_path)

