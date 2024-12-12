<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Google Calendar Events</title>
</head>
<body>
    <h1>Your Google Calendar Events</h1>

    @if(count($events['items']) > 0)
        <ul>
            @foreach ($events['items'] as $event)
                <li>
                    <strong>{{ $event['summary'] }}</strong>
                    <p>{{ \Carbon\Carbon::parse($event['start']['dateTime'])->toFormattedDateString() }}</p>
                </li>
            @endforeach
        </ul>
    @else
        <p>No events found.</p>
    @endif
</body>
</html>
