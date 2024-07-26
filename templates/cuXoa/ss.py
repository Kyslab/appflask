@app.route('/delete_all_files', methods=['POST'])
def delete_all_files():
    if 'user_id' not in session:
        flash('Please log in to access this page', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(user.id))

    for filename in os.listdir(user_folder):
        file_path = os.path.join(user_folder, filename)
        if allowed_file(filename):
            os.remove(file_path)

    flash('All files deleted successfully', 'success')
    return redirect(url_for('upload_and_list_files'))
