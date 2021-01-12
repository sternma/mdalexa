# -*- coding: utf-8 -*-

# This sample demonstrates handling intents from an Alexa skill using the Alexa Skills Kit SDK for Python.
# Please visit https://alexa.design/cookbook for additional examples on implementing slots, dialog management,
# session persistence, api calls, and more.
# This sample is built using the handler classes approach in skill builder.
import logging
import ask_sdk_core.utils as ask_utils
import boto3
import json
import pytz
import datetime
from geopy.geocoders import Nominatim
from geopy.distance import geodesic

from ask_sdk_core.skill_builder import SkillBuilder
from ask_sdk_core.dispatch_components import AbstractRequestHandler
from ask_sdk_core.dispatch_components import AbstractExceptionHandler
from ask_sdk_core.handler_input import HandlerInput
from ask_sdk_core.skill_builder import CustomSkillBuilder
from ask_sdk_core.api_client import DefaultApiClient
from ask_sdk_core.utils import is_request_type, is_intent_name
from ask_sdk_model.ui import AskForPermissionsConsentCard
from ask_sdk_model.services import ServiceException

from ask_sdk_model import Response

sb = CustomSkillBuilder(api_client=DefaultApiClient())

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


ROLEARN = "omitted"
ROLESESSIONNAME = "AssumeRoleSession1"

NOTIFY_MISSING_PERMISSIONS = ("Please enable Location permissions in "
                              "the Amazon Alexa app.")
NO_ADDRESS = ("It looks like you don't have an address set. "
              "You can set your address from the companion app.")
ERROR = "Uh Oh. Looks like something went wrong."

permissions = ["read::alexa:device:all:address"]
# Location Consent permission to be shown on the card. More information
# can be checked at
# https://developer.amazon.com/docs/custom-skills/device-address-api.html#sample-response-with-permission-card

#begin helper functions
#should probably move this to a different file later

def get_user_timezone(handler_input):
    req_envelope = handler_input.request_envelope
    service_client_fact = handler_input.service_client_factory
    
    try:
        device_id = req_envelope.context.system.device.device_id
        ups_svc_client = service_client_fact.get_ups_service()
        return ups_svc_client.get_system_time_zone(device_id)
    except ServiceException:
        return ERROR
    except Exception as e:
        raise e

def get_alexa_location(handler_input): #https://github.com/alexa/alexa-skills-kit-sdk-for-python/blob/master/samples/GetDeviceAddress/lambda/py/lambda_function.py
    req_envelope = handler_input.request_envelope
    #response_builder = handler_input.response_builder
    service_client_fact = handler_input.service_client_factory

    if not (req_envelope.context.system.user.permissions and
            req_envelope.context.system.user.permissions.consent_token):
        return NOTIFY_MISSING_PERMISSIONS
    try:
        device_id = req_envelope.context.system.device.device_id
        device_addr_client = service_client_fact.get_device_address_service()
        addr = device_addr_client.get_full_address(device_id)

        if addr.address_line1 is None and addr.state_or_region is None:
            return NO_ADDRESS
        return addr
    except ServiceException:
        return ERROR
    except Exception as e:
        raise e

def get_coordinates(location): #https://data-dive.com/alexa-get-device-location-from-custom-skill
    geolocator = Nominatim(user_agent="millburn-deli")    # Set provider of geo-data 
    address = location.address_line1 + ", " + location.city + ", " + location.state_or_region
    coordinates = geolocator.geocode(address)
    return(coordinates)

def get_closest_location(mylocation):
    sts_client = boto3.client('sts')
    assumed_role_object=sts_client.assume_role(RoleArn=ROLEARN, RoleSessionName=ROLESESSIONNAME)
    credentials=assumed_role_object['Credentials']
    s3 = boto3.resource('s3',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name='us-east-1')
    bucket = s3.create_bucket(Bucket='millburndeli.com')
    key = 'locations.json'
    #retrieve locations
    obj = s3.Object(bucket.name, key)
    s_object = obj.get()['Body'].read().decode('utf-8')
    data = json.loads(s_object)
    #compare distances
    min_dis = 100000
    count = 0
    loc = -1
    myloc = (mylocation.latitude,mylocation.longitude)
    for restaurant in data['locations']:
        resloc = restaurant['gps'].split(",")
        tmp = geodesic(myloc,resloc).miles
        if tmp<min_dis:
            min_dis = tmp
            loc = count
        count += 1
    return(loc,data['locations'][loc]['name'])

def is_in_range(start, end, current):
    """Return true if current is in the range [start, end]"""
    if start <= end:
        return start <= current <= end
    else:
        return start <= current or current <= end

class LaunchRequestHandler(AbstractRequestHandler):
    """Handler for Skill Launch."""
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool

        return ask_utils.is_request_type("LaunchRequest")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speak_output = "<amazon:emotion name='excited' intensity='medium'>Welcome to Millburn Deli! Ask me about our hours, our locations, or what the sandwich of the month is!</amazon:emotion>"

        return (
            handler_input.response_builder
                .speak(speak_output)
                .ask(speak_output)
                .response
        )

class HoursIntentHandler(AbstractRequestHandler):
        
    """Handler for Hours Intent."""
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_intent_name("HoursIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        #find closest location
        location = (get_alexa_location(handler_input))
        if location==NO_ADDRESS: #IMPLEMENT A BETTER RESPONSE HERE
            return handler_input.response_builder.speak(NO_ADDRESS + "Please check our website, millburndeli.com, to find the hours at the location closest to you.").response
        elif location==NOTIFY_MISSING_PERMISSIONS:
            response_builder.set_card(AskForPermissionsConsentCard(permissions=permissions))
            return handler_input.response_builder.speak(NOTIFY_MISSING_PERMISSIONS)
        elif location==ERROR:
            return handler_input.response_builder.speak(ERROR)
        closest = get_closest_location(get_coordinates(location))
        #get hours
        sts_client = boto3.client('sts')
        assumed_role_object=sts_client.assume_role(RoleArn=ROLEARN, RoleSessionName=ROLESESSIONNAME)
        credentials=assumed_role_object['Credentials']
        s3 = boto3.resource('s3',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name='us-east-1')
        bucket = s3.create_bucket(Bucket='millburndeli.com')
        key = 'locations.json'
        #retrieve hours
        obj = s3.Object(bucket.name, key)
        s_object = obj.get()['Body'].read().decode('utf-8')
        data = json.loads(s_object)
        #determine current day and timezone
        user_timezone = pytz.timezone(get_user_timezone(handler_input))
        today = (datetime.datetime.utcnow().replace(tzinfo=pytz.utc)).astimezone(user_timezone)
        day = today.weekday()
        openstr = data['locations'][closest[0]]['hours'][day]['open'].split(":")
        opentime = datetime.time(int(openstr[0]),int(openstr[1]),0)
        closestr = data['locations'][closest[0]]['hours'][day]['close'].split(":")
        closetime = datetime.time(int(closestr[0]),int(closestr[1]),0)
        #build response
        if openstr[0] != "none":
            is_open = is_in_range(opentime,closetime,today.time())
            if is_open:
                speak_output = "Our closest location to you, " + closest[1] + ", is currently open until " + closetime.strftime("%I:%M %p")  # EVENTUALLY OFFER TO PLACE TOGO ORDER AT THIS TIME
        else:
            speak_output = "Our closest location to you, " + closest[1] + ", is currently closed."  # ADD IN CHECK TO SEE IF IT OPENS TOMORROW AND AT WHAT TIME
        return (handler_input.response_builder.speak(speak_output).response)

class LocationsIntentHandler(AbstractRequestHandler):
    """Handler for Locations Intent."""
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_intent_name("LocationsIntent")(handler_input)

    def handle(self, handler_input):
        sts_client = boto3.client('sts')
        assumed_role_object=sts_client.assume_role(RoleArn=ROLEARN, RoleSessionName=ROLESESSIONNAME)
        credentials=assumed_role_object['Credentials']
        s3 = boto3.resource('s3',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name='us-east-1')
        bucket = s3.create_bucket(Bucket='millburndeli.com')
        key = 'locations.json'
        # type: (HandlerInput) -> Response
        #retrieve locations
        obj = s3.Object(bucket.name, key)
        s_object = obj.get()['Body'].read().decode('utf-8')
        data = json.loads(s_object)
        #build response
        speak_output = "Millburn Deli has locations in"
        for location in data['locations'][:-1]:
            speak_output += " " + location['name'] + ", "
        speak_output += "and " + data['locations'][-1]['name'] + "."
        return (
            handler_input.response_builder
                .speak(speak_output)
                .ask("If you'd like to know more about a location, just say, tell me more about Millburn, for example.")
                .response
        )

class SOTMIntentHandler(AbstractRequestHandler):
    """Handler for Sandwich of the Month Intent."""
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_intent_name("SOTMIntent")(handler_input)

    def handle(self, handler_input):
        sts_client = boto3.client('sts')
        assumed_role_object=sts_client.assume_role(RoleArn=ROLEARN, RoleSessionName=ROLESESSIONNAME)
        credentials=assumed_role_object['Credentials']
        s3 = boto3.resource('s3',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name='us-east-1')
        bucket = s3.create_bucket(Bucket='millburndeli.com')
        key = 'sotm.json'
        # type: (HandlerInput) -> Response
        #retrieve updated sammy of the month
        obj = s3.Object(bucket.name, key)
        s_object = obj.get()['Body'].read().decode('utf-8')
        sandwich = json.loads(s_object)
        #build response
        speak_output = "The sandwich of the month is " + sandwich['name'] + ", which has " + sandwich['contents'] + "."
        if sandwich['pressed'] == "true": #check if sandwich is pressed
            speak_output += " This is a pressed sandwich."

        return (
            handler_input.response_builder
                .speak(speak_output)
                # .ask("add a reprompt if you want to keep the session open for the user to respond")
                # future: prompt user to start a togo order with this sandwich
                .response
        )


class HelpIntentHandler(AbstractRequestHandler):
    """Handler for Help Intent."""
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_intent_name("AMAZON.HelpIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speak_output = "You can ask me about our hours, our locations, or what the sandwich of the month is."

        return (
            handler_input.response_builder
                .speak(speak_output)
                .ask(speak_output)
                .response
        )


class CancelOrStopIntentHandler(AbstractRequestHandler):
    """Single handler for Cancel and Stop Intent."""
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return (ask_utils.is_intent_name("AMAZON.CancelIntent")(handler_input) or
                ask_utils.is_intent_name("AMAZON.StopIntent")(handler_input))

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speak_output = "Goodbye!"

        return (
            handler_input.response_builder
                .speak(speak_output)
                .response
        )


class SessionEndedRequestHandler(AbstractRequestHandler):
    """Handler for Session End."""
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_request_type("SessionEndedRequest")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response

        # Any cleanup logic goes here.

        return handler_input.response_builder.response


class IntentReflectorHandler(AbstractRequestHandler):
    """The intent reflector is used for interaction model testing and debugging.
    It will simply repeat the intent the user said. You can create custom handlers
    for your intents by defining them above, then also adding them to the request
    handler chain below.
    """
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return ask_utils.is_request_type("IntentRequest")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        intent_name = ask_utils.get_intent_name(handler_input)
        speak_output = "You just triggered " + intent_name + "."

        return (
            handler_input.response_builder
                .speak(speak_output)
                # .ask("add a reprompt if you want to keep the session open for the user to respond")
                .response
        )


class CatchAllExceptionHandler(AbstractExceptionHandler):
    """Generic error handling to capture any syntax or routing errors. If you receive an error
    stating the request handler chain is not found, you have not implemented a handler for
    the intent being invoked or included it in the skill builder below.
    """
    def can_handle(self, handler_input, exception):
        # type: (HandlerInput, Exception) -> bool
        return True

    def handle(self, handler_input, exception):
        # type: (HandlerInput, Exception) -> Response
        logger.error(exception, exc_info=True)

        speak_output = "Sorry, I had trouble doing what you asked. Please try again."

        return (
            handler_input.response_builder
                .speak(speak_output)
                #.ask(speak_output)
                .response
        )

# The SkillBuilder object acts as the entry point for your skill, routing all request and response
# payloads to the handlers above. Make sure any new handlers or interceptors you've
# defined are included below. The order matters - they're processed top to bottom.


sb.add_request_handler(HoursIntentHandler())
sb.add_request_handler(LocationsIntentHandler())
sb.add_request_handler(LaunchRequestHandler())
sb.add_request_handler(SOTMIntentHandler())
sb.add_request_handler(HelpIntentHandler())
sb.add_request_handler(CancelOrStopIntentHandler())
sb.add_request_handler(SessionEndedRequestHandler())
sb.add_request_handler(IntentReflectorHandler()) # make sure IntentReflectorHandler is last so it doesn't override your custom intent handlers

sb.add_exception_handler(CatchAllExceptionHandler())

lambda_handler = sb.lambda_handler()