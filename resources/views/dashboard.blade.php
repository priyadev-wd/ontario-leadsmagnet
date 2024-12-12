<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <title>Google Connect</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .img {
                width: 140px;
                height: 140px;
                display: block;
                margin: 15px auto;
            }
        </style>
    </head>
    <body >
        <div class="container d-flex justify-content-center align-items-center mt-5">
            <div class="card mt-2" style="width:400px">
                <img class="card-img-top img" src="{{ asset('images/google.png') }}" alt="Card image">
                <div class="card-body">
                  <div class="d-flex justify-content-center align-items-center">
                  <a href="{{ route('redirect') }}" class="btn btn-secondary">Connect Google Calendar</a>
                  </div>
                </div>
            </div>
        </div>
    </body>
</html>


