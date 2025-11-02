import cloudinary
import cloudinary.uploader
import os


cloudinary.config(
    CLOUDINARY_CLOUD_NAME= os.getenv("CLOUDINARY_CLOUD_NAME"),
    CLOUDINARY_API_KEY= os.getenv("CLOUDINARY_API_KEY"),
    CLOUDINARY_API_SECRET = os.getenv("CLOUDINARY_API_SECRET"),
    secure = True
)

def upload_avatar(file):
    result= cloudinary.uploader.upload(file, folder="avatars")
    return result["secure_url"]

def upload_file(file):
    result= cloudinary.uploader.upload(file, folder="files", resource_type="auto")
    return result["secure_url"]