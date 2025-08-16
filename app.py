from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Replace with a real secret key

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # Get form data
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        # Here you would typically:
        # 1. Validate the data again (server-side)
        # 2. Save to database or send email
        
        flash('Your message has been sent successfully! We will get back to you soon.', 'success')
        return redirect(url_for('contact'))
    
    return render_template('contact.html')

@app.route('/enroll')
def enroll():
    return render_template('enroll.html')

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/courses')
def courses():
    return render_template('courses.html')



@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/course_details')
def course_details():
    return render_template('course_details.html')

@app.route('/course_details2')
def course_details2():
    return render_template('course_details2.html')

@app.route('/course_details3')
def course_details3():
    return render_template('course_details3.html')

@app.route('/course_details4')
def course_details4():
    return render_template('course_details4.html')

@app.route('/course_details5')
def course_details5():
    return render_template('course_details5.html')

@app.route('/course_details6')
def course_details6():
    return render_template('course_details6.html')

if __name__ == '__main__':
    app.run(debug=True)