<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class GoogleCalenderEvent extends Model
{
    use HasFactory;
    protected $guarded = [];
    protected $table = "google_calender_events";
}
