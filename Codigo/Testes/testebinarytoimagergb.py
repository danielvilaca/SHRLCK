import numpy as np
import matplotlib.pyplot as plt
import cv2
import os

def file_to_rgb_image(file_path, output_path):
    # Read file as binary
    with open(file_path, "rb") as f:
        byte_data = f.read()

    # Convert to numpy array
    byte_array = np.frombuffer(byte_data, dtype=np.uint8)

    # Determine image size (square shape preferred)
    img_size = int(np.ceil(np.sqrt(len(byte_array) / 3)))  # Divide by 3 for RGB channels

    # Pad byte array if needed
    padded_array = np.pad(byte_array, (0, img_size**2 * 3 - len(byte_array)), mode='constant', constant_values=0)

    # Reshape into 3D image (RGB)
    image = padded_array.reshape((img_size, img_size, 3))

    # Save image
    cv2.imwrite(output_path, image)

    # Display image
    plt.imshow(image)
    plt.title("Binary File RGB Visualization")
    plt.axis("off")
    plt.show()

    print(f"Image saved as {output_path}")

if __name__ == "__main__":
    file_path = input("Enter the path to the binary file: ")
    output_path = input("Enter the path to save the output image: ")

    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        print("Error: File not found or invalid.")
    else:
        file_to_rgb_image(file_path, output_path)
