<?php

namespace App\Http\Controllers;

use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;  // You can use Laravel's HTTP client or Guzzle directly
use GuzzleHttp\Client;
use App\Models\GoogleToken;
use App\Models\GoogleCalenderEvent;
use Illuminate\Support\Facades\File;
use DateTime;
use DateTimeZone;


class GoogleOAuthController extends Controller
{

    protected $increase;

    public function __construct()
    {
        $this->increase = 0;
    }
    // Redirect to Google OAuth authorization screen
    public function redirectToGoogle()
    {
        $clientId = env('GOOGLE_CLIENT_ID');
        $redirectUri = env('GOOGLE_REDIRECT_URI');
        $scope = env('GOOGLE_SCOPE');
        $googleOAuthUrl = "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&scope={$scope}&redirect_uri={$redirectUri}&client_id={$clientId}&access_type=offline";
        //dd(route('calendar.events.handle.webhook'));
        return redirect()->away($googleOAuthUrl);
    }



    // Handle the callback from Google and exchange the code for an access token
    public function handleGoogleCallback(Request $request)
    {
        $code = $request->get('code');  // Authorization code from Google

        if (!$code) {
            \Log::info("Authorization code is missing");
            dd('Authorization code is missing');
        }

        // Google OAuth Token URL
        $tokenUrl = "https://oauth2.googleapis.com/token";

        $clientId = env('GOOGLE_CLIENT_ID');
        $clientSecret = env('GOOGLE_CLIENT_SECRET');
        $redirectUri = env('GOOGLE_REDIRECT_URI');

        // Send request to exchange code for access token
        $httpClient = new Client();
        $response = $httpClient->post($tokenUrl, [
            'form_params' => [
                'code' => $code,
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
                'redirect_uri' => $redirectUri,
                'grant_type' => 'authorization_code',
            ]
        ]);

        $data = json_decode($response->getBody()->getContents(), true);
        $storeData = [];
        if (isset($data['access_token'])) {
            $storeData['google_access_token'] = $data['access_token'];
        }
        if (isset($data['refresh_token'])) {
            $storeData['google_refresh_token'] = $data['refresh_token'];
        }
        if (isset($data['scope'])) {
            $storeData['google_scope'] = $data['scope'];
        }
        if (isset($data['token_type'])) {
            $storeData['google_token_type'] = $data['token_type'];
        }


        // Store tokens in session or database
        // session(['google_access_token' => $data['access_token']]);
        $accessToken = $data['access_token'];
        $webhookUrl = route('calendar.events.handle.webhook');
        $url = 'https://www.googleapis.com/calendar/v3/calendars/primary/events/watch';

        // Unique ID for the channel
        $channelId = uniqid();

        // Request body
        $postData = [
            'id' => $channelId,  // Unique identifier for the channel
            'type' => 'web_hook',
            'address' => $webhookUrl,  // Your webhook endpoint
        ];

        $storeData['google_channel_id'] = $channelId;
        // Initialize cURL
        $ch = curl_init($url);

        // Set cURL options
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            "Authorization: Bearer $accessToken",
            'Content-Type: application/json',
        ]);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($postData));

        // Execute the request
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        // Close cURL
        curl_close($ch);

        if ($httpCode === 200) {
            $responseData = json_decode($response, true);
            if (GoogleToken::count() > 0) {
                // If the table is not empty, update the first record (you can add a condition here if you want to update a specific record)
                $existingToken = GoogleToken::first();
                $existingToken->update($storeData);
            } else {
                $newToken = new GoogleToken();
                $newToken->fill($storeData);
                $newToken->save();
            }

            return redirect()->route('home')->with('success', 'Google Calendar access granted successfully!');
           /*  return [
                 'success' => true,
                 'response' => $responseData
             ];*/
        } else {
            return [
                'success' => false,
                'error' => $response,
            ];
        }
    }


    public function handleWebhook(Request $request)
    {
        $headers = $request->headers->all();
        $body = $request->all();

        // Log received data for debugging purposes
       //  \Log::info("header",$headers);
       //  \Log::info("body", $body);
       // \Log::info(Carbon::now());
        $now = new DateTime('now', new DateTimeZone('UTC'));
        // Subtract 2 seconds
        $now->modify('-10 seconds');
        $iso8601 = $now->format('Y-m-d\TH:i:s.u') . 'Z';
        // Check if resource state is 'sync' (indicating new or modified event)
        if (isset($headers['x-goog-resource-state']) && $headers['x-goog-resource-state'][0] == 'exists') {
            $resourceId = $headers['x-goog-resource-id'][0]; // Get the resource ID of the event
            $this->fetchEventDetails($resourceId, $iso8601);
        }
    }

    // Fetch event details from Google Calendar based on resource ID
    private function fetchEventDetails($resourceId, $iso8601)
    {
        $existingToken = GoogleToken::first();
        $google_refresh_token = $existingToken->google_refresh_token;
        if (!$google_refresh_token) {
            \Log::error('Access token is missing');
            dd('Access token is missing');
        }

        $accessToken = $this->refreshAccessToken($google_refresh_token);
       // \Log::info("iso8601");
       // \Log::info($iso8601);
        $response = Http::withHeaders([
            'Authorization' => "Bearer {$accessToken}"
        ])->get("https://www.googleapis.com/calendar/v3/calendars/primary/events?maxResults=1&updatedMin=" . $iso8601 . "&showDeleted=true");

        $event = $response->json();

        // \Log::info("event");
        // \Log::info($event);
        if (!empty($event['items']))
        {
            $items = $event['items'];
            usort($items, function ($a, $b) {
                return strtotime($b['created']) - strtotime($a['created']);
            });
            // Get the last event (after sorting in descending order, it's the smallest)
            $firstEvent = $items[0];
			//\Log::info("First - event");
           // \Log::info($firstEvent);
            $findEventInDb = GoogleCalenderEvent::where(['event_id' => $firstEvent['id']])->first();
            // if (!$findEventInDb) {
            if ($firstEvent['status'] == "cancelled") {
              //  \Log::info('for delete');
                if ($findEventInDb) {
                    $this->deleteAppointments($findEventInDb->ghl_event_id);
                }
            } else {
               // \Log::info('for create');
                $matchThese = ['event_id' => $firstEvent['id']];
                $new_record = GoogleCalenderEvent::updateOrCreate($matchThese, ['all_data' => json_encode($firstEvent)]);

                if ($new_record->wasRecentlyCreated)
                {

                    // add email, first name, last name, phone, address
                    $eventWithExtraDetails = $this->extractEventDetails($firstEvent);

                    $phone = $eventWithExtraDetails['phone'];
                    if ($phone != "NA") {
                        $extraDetails['phone'] = $phone;
                        $getContactDetails = $this->getContact($extraDetails);
                         \Log::info('getContactDetails');
                        \Log::info($getContactDetails);
                        \Log::info('Increment ' . $this->increase++);

                        if ($getContactDetails != NULL) {
                            if (count($getContactDetails['contacts']) == 0) {
                                $createContact = $this->createContact($eventWithExtraDetails);
                                \Log::info('Contact Array ');
                                \Log::info($createContact);

                                if (!empty($createContact) && isset($createContact['contact'])) {
                                    if ((isset($createContact['statusCode']) && $createContact['statusCode'] == 400) && isset($createContact['message']) && $createContact['message'] == "This location does not allow duplicated contacts.") {
                                        $createContact = $this->getContactFromGoHighLevel($createContact['meta']['contactId'], env('AUTH_BEARER_TOKEN'));
                                    }
                                    $this->createOrUpdateAppointment($createContact['contact'], $eventWithExtraDetails, $findEventInDb);
                                } else {
                                    $this->createOrUpdateAppointment(["id" => ""], $eventWithExtraDetails, $findEventInDb);
                                }
                            } else {
                                $this->updateContactOnGhl($getContactDetails['contacts'][0]['id'], $eventWithExtraDetails['first_name'], $eventWithExtraDetails['last_name']);
                                $this->createOrUpdateAppointment($getContactDetails['contacts'][0], $eventWithExtraDetails, $findEventInDb);

                            }
                        }
                    }
                }

            }
            // }
        }

        // You can now process the event as per your needs
        // For example, save the event to your database
    }

    public function updateContactOnGhl($id, $firstName, $lastName)
    {
        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_URL => 'https://services.leadconnectorhq.com/contacts/' . $id,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 0,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => 'PUT',
            CURLOPT_POSTFIELDS => json_encode([
                'firstName' => $firstName,
                'lastName' => $lastName
            ]),
            CURLOPT_HTTPHEADER => array(
                'Accept: application/json',
                'Authorization: Bearer '.env('AUTH_BEARER_TOKEN'),
                'Content-Type: application/json',
                'Version: 2021-07-28'
            ),
        ));

        $response = curl_exec($curl);
        curl_close($curl);
        // echo $response;
    }

    public function deleteAppointments($id)
    {
        \Log::info('deleteAppointments');
        \Log::info($id);
        $curl = curl_init();
        curl_setopt_array($curl, [
            CURLOPT_URL => "https://services.leadconnectorhq.com/calendars/events/" . $id,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => "",
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => "DELETE",
            CURLOPT_HTTPHEADER => [
                "Accept: application/json",
                "Authorization: Bearer ".env('AUTH_BEARER_TOKEN'),
                "Version: 2021-04-15"
            ],
        ]);
        $response = curl_exec($curl);
        $err = curl_error($curl);

        curl_close($curl);

        if ($err) {
            echo "cURL Error #:" . $err;
            \Log::info($err);
        } else {
            $decodedResponse = json_decode($response, true);
            GoogleCalenderEvent::where(['ghl_event_id' => $id])->delete();
            \Log::info($decodedResponse);
        }
    }

    public function getContact($eventData)
    {
		//\Log::info(' Contact PHONE '.$eventData['phone']);
        if (empty($eventData['phone'])) {
            return ["contacts" => []];
        }
        $curl = curl_init();
        curl_setopt_array($curl, [
            CURLOPT_URL => "https://services.leadconnectorhq.com/contacts/?locationId=".env('LOCATION_ID')."&query=" . $eventData['phone'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => "",
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => "GET",
            CURLOPT_HTTPHEADER => [
                "Accept: application/json",
                "Authorization: Bearer ".env('AUTH_BEARER_TOKEN'),
                "Version: 2021-07-28",
            ],
            CURLOPT_SSL_VERIFYPEER => false, // Disable SSL verification
            CURLOPT_SSL_VERIFYHOST => false, // Optionally disable host verification
        ]);

        $response = curl_exec($curl);
        $err = curl_error($curl);
        curl_close($curl);
        return json_decode($response, true);
    }

    public function getContactFromGoHighLevel($contactId, $account_token)
    {
        $curl = curl_init();
        curl_setopt_array($curl, [
            CURLOPT_URL => "https://services.leadconnectorhq.com/contacts/" . $contactId,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => "",
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => "GET",
            CURLOPT_SSL_VERIFYPEER => false, // Disable SSL verification
            CURLOPT_SSL_VERIFYHOST => false, // Optionally disable host verification
            CURLOPT_HTTPHEADER => [
                "Accept: application/json",
                "Authorization: Bearer " . $account_token,
                "Version: 2021-07-28",
            ],
        ]);

        $response = curl_exec($curl);
        $err = curl_error($curl);
        curl_close($curl);
        // dd($err);
        return json_decode($response, true);
    }

    public function refreshAccessToken($google_refresh_token)
    {
        $refreshToken = $google_refresh_token; // Make sure to store it

        if (!$refreshToken) {
            \Log::info("Refresh token is missing");
            dd('Refresh token is missing');
        }

        $tokenUrl = "https://oauth2.googleapis.com/token";
        $clientId = env('GOOGLE_CLIENT_ID');
        $clientSecret = env('GOOGLE_CLIENT_SECRET');

        $httpClient = new Client();
        $response = $httpClient->post($tokenUrl, [
            'form_params' => [
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
                'refresh_token' => $refreshToken,
                'grant_type' => 'refresh_token',
            ]
        ]);

        $data = json_decode($response->getBody()->getContents(), true);
        if (isset($data['access_token'])) {
            $existingToken = GoogleToken::first();
            $existingToken->fill(['google_access_token' => $data['access_token']]);
            $existingToken->update();
            return $data['access_token'];
        } else {
            \Log::info("Failed to refresh access token");
            return "";
        }
    }

    function getTimeSlot($time)
    {
        // Create a DateTime object from the input time
        $dateTime = new DateTime($time);

        // Get the current minute
        $minute = (int) $dateTime->format('i');

        // Calculate the start of the time slot
        $slotStartMinute = floor($minute / 30) * 30;
        $slotEndMinute = $slotStartMinute + 30;

        // Set the start time of the slot
        $dateTime->setTime((int) $dateTime->format('H'), $slotStartMinute);
        $slotStartTime = $dateTime->format('H:i');

        // Set the end time of the slot
        $endDateTime = clone $dateTime; // Clone to keep the original time
        $endDateTime->setTime((int) $endDateTime->format('H'), $slotEndMinute);
        $slotEndTime = $endDateTime->format('H:i');

        return [
            'start_time' => $slotStartTime,
            'end_time' => $slotEndTime,
        ];
    }

    function convertToClientCalemderTimezone($dateTimeString)
    {
        $dateTime = new DateTime($dateTimeString);
        // Set the timezone to Toronto, Canada (EST)
        $clientTimeZone = new DateTimeZone('America/Toronto'); // Adjusts for EST/EDT
        $dateTime->setTimezone($clientTimeZone);

        // Return the formatted DateTime object in UTC
        return $dateTime->format('Y-m-d\TH:i:sP'); // Use ISO 8601 format
    }

    public function createOrUpdateAppointment($contact, $appointment, $findEventInDb)
    {
        \Log::info("Create Appointment Function 431");
		\Log::info($appointment);

        $curl = curl_init();
         // Check if dateTime is set, otherwise use date and add 30 minutes to the current time
		// Get current date and time
		$currentDateTime = new DateTime();

		// Check if dateTime is set for start time, otherwise use current time
		if (isset($appointment['start']['dateTime'])) {
			$startTime = $appointment['start']['dateTime'];
		} else {
			$startDate = $appointment['start']['date'];
			// Use current time for start time on the given date
			$startDateTime = new DateTime($startDate . ' ' . $currentDateTime->format('H:i:s'));
			$startTime = $startDateTime->format('Y-m-d\TH:i:sP'); // Format to 'Y-m-d\TH:i:sP' including timezone
		}

		// Check if dateTime is set for end time, otherwise add 30 minutes to the start time
		if (isset($appointment['end']['dateTime'])) {
			$endTime = $appointment['end']['dateTime'];
		} else {
			$endDate = $appointment['end']['date'];
			// Use current time for end time on the given date and add 30 minutes
			$endDateTime = new DateTime($endDate . ' ' . $currentDateTime->format('H:i:s'));
			$endDateTime->modify('+30 minutes');
			$endTime = $endDateTime->format('Y-m-d\TH:i:sP'); // Format to 'Y-m-d\TH:i:sP' including
		}


        $oldEvent = !empty($findEventInDb) ? true : false;
        $url = "https://services.leadconnectorhq.com/calendars/events/appointments";
        $requestMethod = "POST";

        if ($oldEvent == true) {
            $url = "https://services.leadconnectorhq.com/calendars/events/appointments/" . $findEventInDb->ghl_event_id;
            $requestMethod = "PUT";
        }

		\Log::info(" URL HIT ".$url." Request Method ". $requestMethod);
		\Log::info(" calendarId ".env('CALENDAR_ID')." locationId ". env('LOCATION_ID'). " contactId:= ". $contact['id']. " startTime" .$this->convertToClientCalemderTimezone($startTime). " endTime ".$this->convertToClientCalemderTimezone($endTime). " title " . $appointment['summary'] );

        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => "",
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => $requestMethod,
            CURLOPT_POSTFIELDS => json_encode([
                'calendarId' => env('CALENDAR_ID'),
                'locationId' => env('LOCATION_ID'),
                'contactId' => $contact['id'],
                'startTime' => $this->convertToClientCalemderTimezone($startTime),
                'endTime' => $this->convertToClientCalemderTimezone($endTime),
                'title' => $appointment['summary'],
                'meetingLocationType' => 'default',
                'appointmentStatus' => 'confirmed',
                'assignedUserId' => env('ASSIGNED_USER_ID'),
                'address' => 'Google Calender',
                'ignoreDateRange' => true,
                'toNotify' => true,
                'ignoreFreeSlotValidation' => true,
            ]),
            CURLOPT_HTTPHEADER => [
                "Accept: application/json",
                "Authorization: Bearer ".env('AUTH_BEARER_TOKEN'),
                "Content-Type: application/json",
                "Version: 2021-04-15",
            ],
            CURLOPT_SSL_VERIFYPEER => false, // Disable SSL verification
            CURLOPT_SSL_VERIFYHOST => false, // Optionally disable host verification
        ]);
        $response = curl_exec($curl);
        \Log::info("appointment");
        \Log::info($appointment);
		\Log::info("API RESPONSE");
		\Log::info($response);

        $err = curl_error($curl);

        curl_close($curl);
        if ($err) {
            \Log::info($err);
            echo "cURL Error #:" . $err;
        } else {
            $decodedResponse = json_decode($response, true);
            \Log::info("decodedResponse");
            \Log::info($decodedResponse);
            if ($oldEvent == false) {
                $findEventInDb = GoogleCalenderEvent::where(['event_id' => $appointment['id']])->first();
                $findEventInDb->fill(['ghl_event_id' => $decodedResponse['id']]);
                $findEventInDb->update();
            }
            \Log::info("response");
            \Log::info($response);
        }
    }

   /* function extractEventDetails($event)
    {
        $eventTitle = $event['summary'];
        // Define regex patterns for name, phone number, and address
        $phonePattern = '/\(?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\)?/'; // Matches phone numbers with or without hyphens or spaces
        $namePattern = '/([a-zA-Z]+)\s?([a-zA-Z]+)?\s?(.*)/'; // Matches first name, optional last name, and remaining part as address
        $addressPattern = '/(?:\(?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\)?)(.*)/'; // Matches the address after the phone number

        preg_match($phonePattern, $eventTitle, $phoneMatches); // Find the phone number
        preg_match($namePattern, $eventTitle, $nameMatches); // Find the name
        preg_match($addressPattern, $eventTitle, $addressMatches); // Find the address

        // Clean up phone number (remove spaces or hyphens)
        $phone = isset($phoneMatches[0]) ? preg_replace('/[-.\s]/', '', $phoneMatches[0]) : null;

        // Create an associative array with the extracted information
        $event['first_name'] = isset($nameMatches[1]) ? $nameMatches[1] : null;
        $event['last_name'] = isset($nameMatches[2]) ? $nameMatches[2] : null;
        $event['address'] = isset($nameMatches[3]) ? trim($nameMatches[3]) : null; // Treat remaining part as address
        $event['phone'] = $phone;

        return $event;
    } */

    function extractEventDetails($event)
    {
        $eventTitle = $event['summary'];
        $prompt = <<<EOD
                Extract the following details from the given text:
                - Name
                - Phone
                - Address
                - Price
                - Description

                Given text: $eventTitle


                Format the output as follows:
                Name: <name>
                Phone: <phone>
                Address: <address>
                Price: <price>
                Description: <description>
                EOD;

        $payload = [
            "model" => "gpt-3.5-turbo",
            "messages" => [
                [
                    "role" => "system",
                    "content" => "You are a helpful assistant that extracts specific details from text.",
                ],
                [
                    "role" => "user",
                    "content" => $prompt,
                ],
            ],
        ];

        $curl = curl_init();

        curl_setopt_array($curl, array(
            CURLOPT_URL => 'https://api.openai.com/v1/chat/completions',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 0,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_POSTFIELDS => json_encode($payload),
            CURLOPT_HTTPHEADER => array(
                'Content-Type: application/json',
                'Authorization: Bearer '.env('OPEN_AI_KEY'),
            ),
        ));

        $response = curl_exec($curl);
        $responseData = json_decode($response, true);

        $err = curl_error($curl);
        curl_close($curl);
        if ($err) {
            \Log::info($err);
            echo "cURL Error #:" . $err;
        }

        $details = [
            'Name' => 'NA',
            'Phone' => 'NA',
            'Address' => 'NA',
            'Price' => 'NA',
            'Description' => 'NA'
        ];

        if(array_key_exists('error', $responseData))
        {
            \Log::info($responseData['error']['message']);
            echo "cURL Error #:" . $err;
        }
        else
        {
            if (isset($responseData['choices'][0]['message']['content'])) {
                // Extract the content from the response
                $content = $responseData['choices'][0]['message']['content'];

                // Split the content by lines
                $lines = explode("\n", $content);

                // Iterate through the lines and extract the details
                foreach ($lines as $line) {
                    if (strpos($line, 'Name:') !== false) {
                        $details['Name'] = trim(str_replace('Name:', '', $line));
                    } elseif (strpos($line, 'Phone:') !== false) {
                        $details['Phone'] = trim(str_replace('Phone:', '', $line));
                    } elseif (strpos($line, 'Address:') !== false) {
                        $details['Address'] = trim(str_replace('Address:', '', $line));
                    } elseif (strpos($line, 'Price:') !== false) {
                        $details['Price'] = trim(str_replace('Price:', '', $line));
                    } elseif (strpos($line, 'Description:') !== false) {
                        $details['Description'] = trim(str_replace('Description:', '', $line));
                    }
                }
            }
        }

        // Create an associative array with the extracted information
        $event['first_name'] = $details['Name'] ?? null;
        $event['last_name'] = null;
        $event['address'] = $details['Address'] ;
        $event['phone'] = $details['Phone'];

        return $event;
    }

    public function createContact($eventData)
    {
        //\Log::info('createContact 451');
        //\Log::info('details 453', $eventData);
        $address = isset($eventData['address']) ? $eventData['address'] : $eventData['summary'];
         $email = null;
        $curl = curl_init();
        curl_setopt_array($curl, [
            CURLOPT_URL => "https://services.leadconnectorhq.com/contacts/",
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => "",
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => "POST",
            CURLOPT_SSL_VERIFYPEER => false, // Disable SSL verification
            CURLOPT_SSL_VERIFYHOST => false, // Optionally disable host verification
            CURLOPT_POSTFIELDS => json_encode([
                'firstName' => $eventData['first_name'],
                'lastName' => $eventData['last_name'],
                'name' => $eventData['first_name'] . ' ' . $eventData['last_name'],
                'email' => null,
                'locationId' => env('LOCATION_ID'),
                'gender' => "",
                'phone' => $eventData['phone'],
                'address1' => $address,
                'city' => "",
                'state' => "",
                'postalCode' => "",
                'website' => null,
                'timezone' => null,
                'dnd' => true,
                'dndSettings' => [
                    'Call' => [
                        'status' => 'active',
                        'message' => 'home phone',
                        'code' => $eventData['phone'],
                    ],
                    'Email' => [
                        'status' => 'inactive',
                        'message' => 'string',
                        'code' => 'string',
                    ],
                    'SMS' => [
                        'status' => 'inactive',
                        'message' => 'string',
                        'code' => 'string',
                    ],
                    'WhatsApp' => [
                        'status' => 'active',
                        'message' => 'other phone',
                        'code' => $eventData['phone'],
                    ],
                    'GMB' => [
                        'status' => 'inactive',
                        'message' => 'string',
                        'code' => 'string',
                    ],
                    'FB' => [
                        'status' => 'inactive',
                        'message' => 'string',
                        'code' => 'string',
                    ],
                ],
                'inboundDndSettings' => [
                    'all' => [
                        'status' => 'inactive',
                        'message' => 'string',
                    ],
                ],
                'tags' => ['GCal'],
                'customFields' => [],
                'source' => 'public api',
                'country' => "US",
                'companyName' => '',
                'assignedTo' => '',
            ]),
            CURLOPT_HTTPHEADER => [
                "Accept: application/json",
                "Authorization: Bearer ".env('AUTH_BEARER_TOKEN'),
                "Content-Type: application/json",
                "Version: 2021-07-28",
            ],
        ]);

        $response = curl_exec($curl);
        \Log::info("534");
        $err = curl_error($curl);
        curl_close($curl);
        if ($err) {
            echo "cURL Error #:" . $err;
            \Log::info("create contact error");
            \Log::info($err);
        } else {
            \Log::info("create contact success");
            // \Log::info([
            //     'firstName' => $eventData['first_name'],
            //     'lastName' => $eventData['last_name'],
            //     'name' => $eventData['first_name'] . ' ' . $eventData['last_name'],
            //     'email' => $email,
            //     'locationId' => env('LOCATION_ID'),
            //     'gender' => "",
            //     'phone' => $eventData['phone'],
            //     'address1' => $address,
            //     'city' => "",
            //     'state' => "",
            //     'postalCode' => "",
            //     'website' => null,
            //     'timezone' => null,
            //     'dnd' => true,
            //     'dndSettings' => [
            //         'Call' => [
            //             'status' => 'active',
            //             'message' => 'home phone',
            //             'code' => $eventData['phone'],
            //         ],
            //         'Email' => [
            //             'status' => 'inactive',
            //             'message' => 'string',
            //             'code' => 'string',
            //         ],
            //         'SMS' => [
            //             'status' => 'inactive',
            //             'message' => 'string',
            //             'code' => 'string',
            //         ],
            //         'WhatsApp' => [
            //             'status' => 'active',
            //             'message' => 'other phone',
            //             'code' => $eventData['phone'],
            //         ],
            //         'GMB' => [
            //             'status' => 'inactive',
            //             'message' => 'string',
            //             'code' => 'string',
            //         ],
            //         'FB' => [
            //             'status' => 'inactive',
            //             'message' => 'string',
            //             'code' => 'string',
            //         ],
            //     ],
            //     'inboundDndSettings' => [
            //         'all' => [
            //             'status' => 'inactive',
            //             'message' => 'string',
            //         ],
            //     ],
            //     'tags' => [],
            //     'customFields' => [],
            //     'source' => 'public api',
            //     'country' => "US",
            //     'companyName' => '',
            //     'assignedTo' => '',
            // ]);
            \Log::info($response);
            return json_decode($response, true);
        }
    }
}
