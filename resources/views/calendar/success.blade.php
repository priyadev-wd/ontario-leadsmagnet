<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Google Calendar Access Success</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-KyZXEJ01VCJ0Gpdc6Iiv4l6IX6OxWw1gXtkmLl9MZXk+ii1rF7lfk/p7Os80z1K6" crossorigin="anonymous">
    <style>
        body {
            /* background-image: url('https://via.placeholder.com/1200x800'); /* Replace with your background image */
            background-size: cover;
            background-position: center;
            color: white; */
        }
        .content {
            text-align: center;
            margin-top: 150px;
            padding: 30px;
            /* background-color: rgba(0, 0, 0, 0.5); */
            border-radius: 10px;
            color: rgba(0, 0, 0, 0.5) !important;
        }
        .alert-success {
            margin-top: 20px;
        }
    </style>
</head>
<body>

    <div class="container">
        <div class="content">
            <h1>Google Calendar Access Successful</h1>

            <!-- Success Message (will be shown after successful authorization) -->
            @if(session('success'))
                <div class="alert alert-success">
                    <strong>Success!</strong> {{ session('success') }}
                </div>
            @endif
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js" integrity="sha384-pzjw8f+ua7Kw1TIq0Ktx2l4M7c5vA0fs06WlEXTOIN5mDg2fDFm6VVoFZVPa2dvo" crossorigin="anonymous"></script>
</body>
</html>
