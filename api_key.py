import os
import yaml
import json
import logging
import importlib
import requests
import datetime
from typing import Dict, Any, Optional, Callable, Union, Tuple
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define the name of the base API key file
BASE_API_KEY_FILE = "base_api_key.yaml"


def get_api_key_metadata(api_key: str = None) -> Dict[str, Any]:
    """
    Get metadata from the API key configuration file.
    This metadata is not included in JWT tokens but can be used for function calls and API requests.
    
    Args:
        api_key: The API key to look up, if None or empty, will use the base API key
    
    Returns:
        Dict containing the metadata from the API key configuration
    """
    try:
        # Get API keys directory path from environment variable or use default
        api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
        
        # Check if directory exists
        if not os.path.exists(api_keys_dir):
            logger.error(f"API keys directory not found: {api_keys_dir}")
            return {}
        
        # Determine which API key file to use
        api_key_file = None
        
        # If API key is provided, try to find its config file
        if api_key:
            specific_key_file = os.path.join(api_keys_dir, f"{api_key}.yaml")
            if os.path.exists(specific_key_file):
                api_key_file = specific_key_file
            else:
                logger.warning(f"Config file for API key not found: {api_key}")
                logger.info("Falling back to base API key")
        
        # If no API key provided or specific key not found, use the base API key
        if not api_key_file:
            base_key_file = os.path.join(api_keys_dir, BASE_API_KEY_FILE)
            if os.path.exists(base_key_file):
                api_key_file = base_key_file
                logger.info("Using base API key")
            else:
                logger.warning(f"Base API key file not found: {BASE_API_KEY_FILE}")
                return {}
        
        # Load API key config from file
        with open(api_key_file, 'r') as f:
            key_data = yaml.safe_load(f)
        
        # Extract metadata section
        metadata = key_data.get('metadata', {})
        
        return metadata
        
    except Exception as e:
        logger.error(f"Unexpected error getting API key metadata: {str(e)}")
        return {}


def get_api_key_data(api_key: str = None, user_context: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Get both claims and metadata from an API key configuration in a single call.
    This is useful for testing scenarios where you need access to both JWT claims and external metadata.
    
    Args:
        api_key: The API key to look up, if None or empty, will use the base API key
        user_context: Optional context about the user (e.g., user_id, team_id)
        
    Returns:
        Dict containing both 'claims' and 'metadata' keys with their respective data
    """
    claims = get_additional_claims(api_key, user_context)
    metadata = get_api_key_metadata(api_key)
    
    return {
        "claims": claims,
        "metadata": metadata
    }

def get_additional_claims(api_key: str = None, user_context: Dict[str, Any] = None) -> Dict:
    """
    Get additional claims based on the provided API key
    
    Args:
        api_key: The API key to look up, if None or empty, will use the base API key
        user_context: Optional context about the user (e.g., user_id, team_id)
        
    Returns:
        Dict with additional claims to include in the JWT token
    """
    try:
        if user_context is None:
            user_context = {}
            
        logger.info(f"[DEBUG] Starting get_additional_claims for API key: {api_key}")
        logger.info(f"[DEBUG] User Context: {user_context}")
        
        # Get API keys directory path from environment variable or use default
        api_keys_dir = os.getenv("API_KEYS_DIR", "config/api_keys")
        
        # Check if directory exists
        if not os.path.exists(api_keys_dir):
            logger.error(f"API keys directory not found: {api_keys_dir}")
            return {}
        
        # Determine which API key file to use
        api_key_file = None
        
        # If API key is provided, try to find its config file
        if api_key:
            specific_key_file = os.path.join(api_keys_dir, f"{api_key}.yaml")
            if os.path.exists(specific_key_file):
                api_key_file = specific_key_file
                logger.info(f"Using specific API key file: {specific_key_file}")
            else:
                logger.warning(f"Config file for API key not found: {api_key}")
                logger.info("Falling back to base API key")
        
        # If no API key provided or specific key not found, use the base API key
        if not api_key_file:
            base_key_file = os.path.join(api_keys_dir, BASE_API_KEY_FILE)
            if os.path.exists(base_key_file):
                api_key_file = base_key_file
                logger.info("Using base API key")
            else:
                logger.warning(f"Base API key file not found: {BASE_API_KEY_FILE}")
                return {}
        
        # Load API key config from file
        with open(api_key_file, 'r') as f:
            key_data = yaml.safe_load(f)
        
        # Extract static claims
        static_claims = key_data.get('claims', {}).get('static', {})
        logger.info(f"[DEBUG] Static claims: {static_claims}")
        
        # Process dynamic claims
        metadata = key_data.get('metadata', {})
        logger.info(f"[DEBUG] Metadata: {metadata}")
        
        dynamic_claims = process_dynamic_claims(
            key_data.get('claims', {}).get('dynamic', {}),
            user_context,
            api_key or "base_api_key",
            key_data.get('id', ''),
            metadata  # Make sure metadata is passed through
        )
        logger.info(f"[DEBUG] Dynamic claims result: {dynamic_claims}")
        
        # Merge claims
        additional_claims = {**static_claims, **dynamic_claims}
        logger.info(f"[DEBUG] Final additional claims: {additional_claims}")
        
        return additional_claims
        
    except Exception as e:
        logger.error(f"Unexpected error getting additional claims: {str(e)}", exc_info=True)
        return {}

def process_dynamic_claims(
    dynamic_claims_config: Dict[str, Any],
    user_context: Dict[str, Any],
    api_key: str,
    api_key_id: str,
    metadata: Dict[str, Any] = None
) -> Dict[str, Any]:
    logger.info(f"Processing dynamic claims with user_context={user_context}, api_key={api_key}, api_key_id={api_key_id}")
    """
    Process dynamic claims configuration and execute the specified functions or API calls
    
    Args:
        dynamic_claims_config: Configuration for dynamic claims
        user_context: Context about the user (e.g., user_id, team_id)
        api_key: The original API key string
        api_key_id: The ID associated with the API key
        
    Returns:
        Dict with resolved dynamic claims
    """
    if not dynamic_claims_config:
        return {}
    
    result = {}
    
    logger.info(f"Dynamic claims config: {dynamic_claims_config}")
    for claim_name, claim_config in dynamic_claims_config.items():
        logger.info(f"Processing claim: {claim_name} with config: {claim_config}")
        try:
            claim_type = claim_config.get('type', '')
            
            if claim_type == 'function':
                claim_value = execute_function_claim(claim_config, user_context, api_key, api_key_id, metadata)
                if claim_value:
                    result[claim_name] = claim_value
                    
            elif claim_type == 'api':
                # Call an external API to get the claim value
                claim_value = execute_api_claim(claim_config, user_context, api_key, api_key_id)
                if claim_value:
                    result[claim_name] = claim_value
                    
            elif claim_type == 'formula':
                # Process formula-based claims
                formulas = claim_config.get('formulas', {})
                formula_claims = execute_formula_claims(formulas, user_context, result, api_key, api_key_id)
                result.update(formula_claims)
                    
            else:
                logger.warning(f"Unknown claim type: {claim_type} for claim: {claim_name}")
                
        except Exception as e:
            logger.error(f"Error processing dynamic claim '{claim_name}': {str(e)}")
    
    logger.info(f"Final dynamic claims result: {result}")
    return result

def execute_function_claim(
    claim_config: Dict[str, Any],
    user_context: Dict[str, Any],
    api_key: str,
    api_key_id: str,
    metadata: Dict[str, Any] = None
) -> Optional[Any]:
    logger.info(f"Executing function claim with config: {claim_config}")
    """
    Execute a function-based dynamic claim
    
    Args:
        claim_config: Configuration for the function claim
        user_context: Context about the user
        api_key: The original API key string
        api_key_id: The ID associated with the API key
        
    Returns:
        The claim value returned by the function, or None if execution failed
    """
    try:
        module_name = claim_config.get('module')
        function_name = claim_config.get('function')
        
        if not module_name or not function_name:
            logger.error("Missing module or function name in function claim configuration")
            return None
        
        # Import the module
        module = importlib.import_module(module_name)
        
        # Get the function
        func = getattr(module, function_name)
        
        # Prepare arguments
        args = claim_config.get('args', {})
        processed_args = {}
        
        # Replace placeholders in arguments with values from context
        for arg_name, arg_value in args.items():
            if isinstance(arg_value, str) and arg_value.startswith('{') and arg_value.endswith('}'):
                # Extract the placeholder name
                placeholder = arg_value[1:-1]
                
                if placeholder == 'api_key':
                    processed_args[arg_name] = api_key
                elif placeholder == 'api_key_id':
                    processed_args[arg_name] = api_key_id
                else:
                    # Look for the value in user_context
                    processed_args[arg_name] = user_context.get(placeholder, '')
            else:
                processed_args[arg_name] = arg_value
        
        # Call the function with the processed arguments and metadata if available
        if metadata is not None:
			logger.info(f"[FUNCTION] Calling with metadata: {metadata}")
            return func(**processed_args, metadata=metadata)
        else:
            return func(**processed_args)
        
    except Exception as e:
        logger.error(f"Error executing function claim: {str(e)}")
        return None

def execute_api_claim(
    claim_config: Dict[str, Any],
    user_context: Dict[str, Any],
    api_key: str,
    api_key_id: str
) -> Optional[Any]:
    """
    Execute an API-based dynamic claim
    
    Args:
        claim_config: Configuration for the API claim
        user_context: Context about the user
        api_key: The original API key string
        api_key_id: The ID associated with the API key
        
    Returns:
        The claim value returned by the API, or None if execution failed
    """
    try:
        url = claim_config.get('url')
        method = claim_config.get('method', 'GET')
        headers = claim_config.get('headers', {})
        response_field = claim_config.get('response_field')
        
        if not url:
            logger.error("Missing URL in API claim configuration")
            return None
        
        # Replace placeholders in URL
        processed_url = url
        for placeholder, value in {
            '{api_key}': api_key,
            '{api_key_id}': api_key_id,
            **{f'{{{k}}}': v for k, v in user_context.items()}
        }.items():
            processed_url = processed_url.replace(placeholder, str(value))
        
        # Replace placeholders in headers
        processed_headers = {}
        for header_name, header_value in headers.items():
            if isinstance(header_value, str) and '{' in header_value and '}' in header_value:
                for placeholder, value in {
                    '{api_key}': api_key,
                    '{api_key_id}': api_key_id,
                    '{internal_token}': os.getenv('INTERNAL_API_TOKEN', ''),
                    **{f'{{{k}}}': v for k, v in user_context.items()}
                }.items():
                    header_value = header_value.replace(placeholder, str(value))
            processed_headers[header_name] = header_value
        
        # Make the API request
        response = requests.request(
            method=method,
            url=processed_url,
            headers=processed_headers,
            timeout=5  # 5 second timeout
        )
        
        # Check if the request was successful
        if response.status_code != 200:
            logger.error(f"API request failed with status code {response.status_code}: {response.text}")
            return None
        
        # Parse the response
        response_data = response.json()
        
        # Extract the specified field if provided
        if response_field:
            # Support for nested fields using dot notation (e.g., "data.user.quota")
            parts = response_field.split('.')
            value = response_data
            for part in parts:
                if part in value:
                    value = value[part]
                else:
                    logger.error(f"Response field '{response_field}' not found in API response")
                    return None
            return value
        
        return response_data
        
    except Exception as e:
        logger.error(f"Error executing API claim: {str(e)}")
        return None


def execute_formula_claims(
    formulas: Dict[str, str],
    user_context: Dict[str, Any],
    existing_claims: Dict[str, Any],
    api_key: str,
    api_key_id: str
) -> Dict[str, Any]:
    """
    Execute formula-based dynamic claims
    
    Args:
        formulas: Dictionary of formula-based claims with claim name as key and formula as value
        user_context: Context about the user
        existing_claims: Claims that have already been processed (static and dynamic)
        api_key: The original API key string
        api_key_id: The ID associated with the API key
        
    Returns:
        Dictionary of evaluated formula claims
    """
    try:
        # If no formulas defined, return empty dict
        if not formulas:
            return {}
            
        # Without using external libraries, we'll implement a basic formula evaluator
        # This is intentionally limited for security reasons
        result = {}
        
        # Define helper functions for formula evaluation
        def now():
            return datetime.now()
            
        def hours(h):
            return timedelta(hours=h)
            
        def days(d):
            return timedelta(days=d)
            
        def min_val(a, b):
            return min(a, b)
            
        def max_val(a, b):
            return max(a, b)
            
        def is_in(item, collection):
            if isinstance(collection, (list, tuple, set)):
                return item in collection
            return False
            
        # Create evaluation context with all available variables
        eval_context = {
            # Include existing claims
            **existing_claims,
            # Include user context
            **user_context,
            # Helper functions
            "now": now,
            "hours": hours,
            "days": days,
            "min": min_val,
            "max": max_val,
            "in": is_in,
            # Constants
            "api_key": api_key,
            "api_key_id": api_key_id,
            "true": True,
            "false": False,
            "null": None
        }
        
        # Process each formula
        for claim_name, formula in formulas.items():
            try:
                # We'll implement a very basic, security-conscious expression evaluator
                # For production, consider a proper, secure formula evaluation library
                
                # 1. Evaluate basic comparisons
                if " == " in formula:
                    left, right = formula.split(" == ", 1)
                    left_val = eval_context.get(left.strip(), left.strip())
                    right_val = eval_context.get(right.strip(), right.strip())
                    
                    # Handle string literals
                    if isinstance(right_val, str) and right_val.startswith("'") and right_val.endswith("'"):
                        right_val = right_val[1:-1]
                    if isinstance(left_val, str) and left_val.startswith("'") and left_val.endswith("'"):
                        left_val = left_val[1:-1]
                        
                    result[claim_name] = (left_val == right_val)
                    
                # 2. Handle ternary operations (x ? y : z)
                elif " ? " in formula and " : " in formula:
                    condition, rest = formula.split(" ? ", 1)
                    true_val, false_val = rest.split(" : ", 1)
                    
                    # Evaluate condition
                    condition_val = eval_context.get(condition.strip(), condition.strip())
                    if condition_val in ("true", True):
                        result[claim_name] = eval_context.get(true_val.strip(), true_val.strip())
                    else:
                        result[claim_name] = eval_context.get(false_val.strip(), false_val.strip())
                
                # 3. Handle basic math operations
                elif "+" in formula or "-" in formula or "*" in formula or "/" in formula:
                    # Very simplified - in a real implementation, use a proper expression parser
                    if "+" in formula:
                        left, right = formula.split("+", 1)
                        left_val = float(eval_context.get(left.strip(), left.strip()))
                        right_val = float(eval_context.get(right.strip(), right.strip()))
                        result[claim_name] = left_val + right_val
                    elif "-" in formula:
                        left, right = formula.split("-", 1)
                        left_val = float(eval_context.get(left.strip(), left.strip()))
                        right_val = float(eval_context.get(right.strip(), right.strip()))
                        result[claim_name] = left_val - right_val
                    elif "*" in formula:
                        left, right = formula.split("*", 1)
                        left_val = float(eval_context.get(left.strip(), left.strip()))
                        right_val = float(eval_context.get(right.strip(), right.strip()))
                        result[claim_name] = left_val * right_val
                    elif "/" in formula:
                        left, right = formula.split("/", 1)
                        left_val = float(eval_context.get(left.strip(), left.strip()))
                        right_val = float(eval_context.get(right.strip(), right.strip()))
                        if right_val != 0:
                            result[claim_name] = left_val / right_val
                        else:
                            result[claim_name] = 0
                
                # 4. Handle function calls
                elif "(" in formula and ")" in formula and formula.split("(")[0].strip() in eval_context:
                    func_name = formula.split("(")[0].strip()
                    if func_name in eval_context and callable(eval_context[func_name]):
                        # Extract argument
                        arg_part = formula.split("(", 1)[1].rsplit(")", 1)[0]
                        
                        # Very simplified argument parsing (just one argument supported)
                        if arg_part in eval_context:
                            arg = eval_context[arg_part]
                        else:
                            # Try to convert to appropriate type
                            if arg_part.isdigit():
                                arg = int(arg_part)
                            elif arg_part.replace('.', '').isdigit() and arg_part.count('.') <= 1:
                                arg = float(arg_part)
                            else:
                                arg = arg_part
                        
                        # Call the function
                        result[claim_name] = eval_context[func_name](arg)
                
                # 5. Direct variable lookup
                elif formula.strip() in eval_context:
                    result[claim_name] = eval_context[formula.strip()]
                    
                # Otherwise keep as string
                else:
                    result[claim_name] = formula
                    
            except Exception as e:
                logger.error(f"Error evaluating formula for claim '{claim_name}': {str(e)}")
        
        return result
    except Exception as e:
        logger.error(f"Error processing formula claims: {str(e)}")
        return {}