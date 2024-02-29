# import pandas as pd
#
#
# def get_excel_headers(file_path):
#     try:
#         # Read the Excel file into a DataFrame
#         df = pd.read_excel(file_path, header=0)  # Assuming headers are in the first row
#
#         # Retrieve the column headers
#         headers = df.columns.tolist()
#
#         return headers
#     except Exception as e:
#         print(f"Error: {e}")
#         return None
#
#
# # Example usage
# excel_file_path = '/home/deeksha/Downloads/Ingenious e-Brain - Final Report - IP Landscape - GLP-1 (Confidential) 1.xlsm'
# headers = get_excel_headers(excel_file_path)
#
# if headers:
#     print("Headers:")
#     for header in headers:
#         print(header)
# else:
#     print("Failed to retrieve headers.")
# import pandas as pd
#
# # Replace 'path/to/your/file.xlsx' with the actual path to your Excel file
# df = pd.read_excel('/home/deeksha/Downloads/Ingenious e-Brain - Final Report - IP Landscape - GLP-1 (Confidential) 1.xlsm', header=[0, 1])
#
# for idx, value in df.items():
#   # Print header level 1 (main header)
#   print(f"Main Header: {idx[0]}")
#
#   # Check if subheader exists (level 1)
#   if pd.api.types.is_list_dtype(idx) and len(idx) > 1:
#     # Print subheader (level 2)
#     print(f"\tSubheader: {idx[1]}")
#   else:
#     print("\tNo subheader")
#
#   # Print separator
#   print("---")
