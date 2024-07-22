
@app.route('/', methods=['GET', 'POST'])
def upload_and_list_files():
    if 'user_id' not in session:
        flash('Please log in to access this page', 'warning')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    total_size = 0
    if request.method == 'POST':
        if 'files' in request.files:
            files = request.files.getlist('files')
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    total_size += os.path.getsize(filepath)
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
    
    total_size = sum(os.path.getsize(os.path.join(app.config['UPLOAD_FOLDER'], f)) for f in files)
    
    cost_per_file = 0.5  # Example cost per file
    cost_per_mb = 0.1  # Example cost per MB

    total_cost = (len(files) * cost_per_file) + ((total_size / (1024 * 1024)) * cost_per_mb)  # Calculate total cost

    return render_template('upload_and_list.html', files=files, user=user, total_cost=total_cost)
