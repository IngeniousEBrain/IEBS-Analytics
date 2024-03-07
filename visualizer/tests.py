import pandas as pd

excel_file_path = '/home/deeksha/Documents/Untitled 1.xlsx'
# excel_file_path = '/home/deeksha/Downloads/PN No.xlsx'
# Read the entire Excel file into a DataFrame
df = pd.read_excel(excel_file_path)


# def dataframe_to_nested_dict(df):
#     nested_dict = {}
#     main_col_name = df.columns[0]
#
#     nested_dict[main_col_name] = df[main_col_name].tolist()
#     for col in df.columns[1:]:
#         nested_dict[col] = list(df[col])
#     return nested_dict
#
#
# nested_data = dataframe_to_nested_dict(df.copy())
# print(nested_data)


def dataframe_to_nested_dict(df):
    nested_dict = {}
    parent_col_name = ''
    for col in df.columns:
        if 'Unnamed' not in col:
            parent_col_name = col
            nested_dict[col] = df[col].tolist()
        else:
            subcolumn_index = col.split('.')[-1]
            nested_dict[f"{parent_col_name}{subcolumn_index}"] = list(df[col])
    return nested_dict


nested_data = dataframe_to_nested_dict(df.copy())
print(nested_data)
