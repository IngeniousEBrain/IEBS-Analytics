from celery import shared_task
import pandas as pd
import math
from django.core.exceptions import ValidationError
from .models import PatentData, CustomUser  # Import your Django model


def handle_nat(dt):
    if pd.isna(dt):
        return None
    else:
        return dt


@shared_task
def process_excel_data_task(user_id, first_row_project_code, file_content):
    try:
        df  = pd.read_excel(file_content)
        user_instance = CustomUser.objects.get(id=user_id.session.get('logged_in_user_id'))
        first_row_project_code = first_row_project_code

        # Clear existing data related to the project
        PatentData.objects.filter(user_id=user_instance,
                                  project_code=first_row_project_code).delete()

        patent_data_rows = []

        for index, row in df.iterrows():
            application_date_str = row['Application Dates']
            publication_date_str = row['Publication Dates']
            expected_expiry_str = row['Expected Expiry Dates']
            earliest_patent_priority_str = row['Earliest Patent Priority Date']
            application_dates = pd.NaT if pd.isna(application_date_str) else pd.to_datetime(
                application_date_str, errors='coerce')
            publication_dates = pd.NaT if pd.isna(publication_date_str) else pd.to_datetime(
                publication_date_str, errors='coerce')
            expected_expiry_dates = pd.NaT if pd.isna(expected_expiry_str) else pd.to_datetime(
                expected_expiry_str, errors='coerce')
            earliest_patent_priority_date = pd.NaT if pd.isna(earliest_patent_priority_str) else pd.to_datetime(
                earliest_patent_priority_str, errors='coerce')
            remaining_life = None
            if not math.isnan(row['Remaining Life']):
                remaining_life = row['Remaining Life']
            citing_patents_count = None
            if not math.isnan(row['Citing Patents - Count']):
                citing_patents_count = row['Citing Patents - Count']
            cited_patents_count = None
            if not math.isnan(row['Cited Patents - Count']):
                cited_patents_count = row['Cited Patents - Count']

            patent_data_dict = {
                'user': user_instance,
                'application_dates': handle_nat(application_dates),
                'publication_dates': handle_nat(publication_dates),
                'expected_expiry_dates': handle_nat(expected_expiry_dates),
                'earliest_patent_priority_date': handle_nat(earliest_patent_priority_date),
                'publication_number': row['Publication Number'],
                'assignee_standardized': row['Assignee - Standardized'],
                'legal_status': row['Legal Status'],
                'remaining_life': remaining_life,
                'cited_patents_count': cited_patents_count,
                'citing_patents_count': citing_patents_count,
                'inventors': row['Inventors'],
                'application_number': row['Application Number'],
                'cpc': row['CPC'],
                'ipc': row['IPC'],
                'e_fan': row['EFAN'],
                'project_code': first_row_project_code
            }
            patent_data_rows.append(patent_data_dict)

        # Bulk create PatentData objects
        PatentData.objects.bulk_create([
            PatentData(**data) for data in patent_data_rows
        ])

    except pd.errors.ParserError as e:
        print("Error parsing Excel file:", str(e))
    except ValidationError as e:
        print("Validation Error:", str(e))
