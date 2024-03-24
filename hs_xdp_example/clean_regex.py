# import re

# # Open the original file
# # with open('snort_patterns.txt', 'r') as file:
# #     patterns = file.readlines()

# # # Remove any parentheses from the patterns
# # cleaned_patterns = [re.sub(r'{[()]}', '', pattern) for pattern in patterns]

# # # Save the cleaned patterns to a new file
# # with open('cleaned_snort_patterns.txt', 'w') as file:
# #     file.writelines(cleaned_patterns)


# def remove_embedded_anchors(pattern):
#     # Remove ^ and $ characters that are not at the start or end of the pattern
#     cleaned_pattern = re.sub(r'(?<!^)\^|\$(?!$)', '', pattern)
#     cleaned_patterns = re.sub(r'^\++', '', pattern)
#     return cleaned_pattern


# # Open the original file
# with open('snort_patterns.txt', 'r') as file:
#     content = file.read()

# # Remove all occurrences of (), {}, and [] from the content
# cleaned_content = content.replace('(', '').replace(')', '').replace(
#     '{', '').replace('}', '').replace('[', '').replace(']', '')

# # Split the cleaned content into individual patterns
# patterns = cleaned_content.split('\n')

# # Remove embedded anchors from each pattern
# cleaned_patterns = [remove_embedded_anchors(
#     pattern.strip()) for pattern in patterns]

# # Save the cleaned patterns to a new file
# with open('cleaned_snort_patterns.txt', 'w') as file:
#     file.write('\n'.join(cleaned_patterns))


import re

def remove_embedded_anchors(pattern):
    # Remove ^ and $ characters that are not at the start or end of the pattern
    pattern = re.sub(r'(?<!^)\^|\$(?!$)', '', pattern)
    # Remove '+' characters at the beginning of the pattern
    pattern = re.sub(r'^\++', '', pattern)
    return pattern

# Open the original file
with open('snort_patterns.txt', 'r') as file:
    content = file.read()

# Remove all occurrences of (), {}, and [] from the content
cleaned_content = content.replace('(', '').replace(')', '').replace(
    '{', '').replace('}', '').replace('[', '').replace(']', '').replace('+', '')

# Split the cleaned content into individual patterns
patterns = cleaned_content.split('\n')

# Remove embedded anchors from each pattern and skip empty lines
cleaned_patterns = [
    remove_embedded_anchors(pattern.strip()) for pattern in patterns if pattern.strip()
]

# Save the cleaned patterns to a new file
with open('cleaned_snort_patterns.txt', 'w') as file:
    file.write('\n'.join(cleaned_patterns))
