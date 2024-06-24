import os
from flask import Flask, request, redirect, url_for, send_file, render_template, flash
from werkzeug.utils import secure_filename
import openpyxl

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PROCESSED_FOLDER'] = 'processed'
app.config['ALLOWED_EXTENSIONS'] = {'xlsx'}

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
if not os.path.exists(app.config['PROCESSED_FOLDER']):
    os.makedirs(app.config['PROCESSED_FOLDER'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/', methods=['GET', 'POST'])
def upload_and_list_files():
    if request.method == 'POST':
        if 'files' in request.files:
            files = request.files.getlist('files')
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
            flash('Files uploaded successfully')
        elif 'merge' in request.form:
            remove_empty_rows = 'remove_empty' in request.form
            text_to_remove_list = request.form.getlist('text_to_remove')

            merged_wb = openpyxl.Workbook()
            merged_ws = merged_wb.active
            merged_ws.title = 'Merged Data'

            for filename in os.listdir(app.config['UPLOAD_FOLDER']):
                if allowed_file(filename):
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    wb = openpyxl.load_workbook(filepath, data_only=True)
                    ws = wb.active
                    for row in ws.iter_rows(values_only=True):
                        if remove_empty_rows and all(cell is None for cell in row):
                            continue
                        if any(text in [str(cell) for cell in row if cell is not None] for text in text_to_remove_list):
                            continue
                        merged_ws.append(row)

            merged_filename = 'merged_file.xlsx'
            merged_filepath = os.path.join(app.config['PROCESSED_FOLDER'], merged_filename)
            merged_wb.save(merged_filepath)
            flash('Files merged successfully')
            return redirect(url_for('download_file', filename=merged_filename))

    files = os.listdir(app.config['UPLOAD_FOLDER'])
    files = [f for f in files if allowed_file(f)]
    return render_template('upload_and_list.html', files=files)

@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash(f'File {filename} deleted successfully')
    else:
        flash(f'File {filename} not found')
    return redirect(url_for('upload_and_list_files'))

@app.route('/download/<filename>')
def download_file(filename):
    file_path = os.path.join(app.config['PROCESSED_FOLDER'], filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return "File not found", 404

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
