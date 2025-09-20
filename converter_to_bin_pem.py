import sys
import os
import base64

#############################################################################
## use this script to make files from the strings the server prints to you ##
## pick a path for your files (ends with .bin or .pem), then paste the     ##
## string from the server, then b for bin and p for pem.                   ##
#############################################################################

def main():
    if len(sys.argv) != 4 or sys.argv[3] not in ["b","p"]:
        print(f"Usage: python {sys.argv[0]} <output_path> <text> <b for bin p for pem>")
        sys.exit(1)

    output_path = sys.argv[1]
    text_str = sys.argv[2]
    b_p = sys.argv[3]

    if b_p == "b":
        # Convert base64 string to bytes
        cipher_bytes = base64.b64decode(text_str)

        # Write to .bin file
        with open(output_path, "wb") as f:
            f.write(cipher_bytes)

        print(f"Binary file created at: {output_path}")
    elif b_p == "p":
        with open(output_path, "w") as f:
            f.write(text_str)

        print(f"PEM file created at: {output_path}")

if __name__ == "__main__":
    main()
