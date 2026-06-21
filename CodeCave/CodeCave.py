import pefile
import sys


def find_code_caves(pe_file_path, min_cave_size=32):
    try:
        pe = pefile.PE(pe_file_path)
    except Exception as e:
        print(f"Error loading PE file: {e}")
        return []
    
    caves = []
    
    # Check each section
    for section in pe.sections:
        section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        section_data = section.get_data()
        
        cave_start = None
        cave_size = 0
        
        # Look for sequences of null or 0xFF bytes
        for i, byte in enumerate(section_data):
            if byte in (0x00, 0xFF, 0xCC):  # Common padding bytes
                if cave_start is None:
                    cave_start = i
                cave_size += 1
            else:
                if cave_size >= min_cave_size and cave_start is not None:
                    offset = section.PointerToRawData + cave_start
                    caves.append((offset, cave_size, section_name))
                cave_start = None
                cave_size = 0
        
        # Check if cave extends to end of section
        if cave_size >= min_cave_size and cave_start is not None:
            offset = section.PointerToRawData + cave_start
            caves.append((offset, cave_size, section_name))
    
    return caves


def print_caves(caves):
    if not caves:
        print("No code caves found.")
        return
    
    print(f"Found {len(caves)} code cave(s):\n")
    print(f"{'Offset':<12} {'Size':<12} {'Section':<20}")
    print("-" * 44)
    
    for offset, size, section in caves:
        print(f"0x{offset:<10X} {size:<12} {section:<20}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python CodeCave.py <pe_file_path> [min_cave_size]")
        sys.exit(1)
    
    pe_file = sys.argv[1]
    min_size = int(sys.argv[2]) if len(sys.argv) > 2 else 32
    
    caves = find_code_caves(pe_file, min_size)
    print_caves(caves)


if __name__ == "__main__":
    main()
