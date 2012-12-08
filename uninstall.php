<?php
/*
 * WP WAF Uninstall
 *
 * @since 1.0
 */


// Check for the 'WP_UNINSTALL_PLUGIN' constant, before executing
if( !defined( 'ABSPATH' ) && !defined( 'WP_UNINSTALL_PLUGIN' ) )
	exit();

// Delete options from the database
delete_option( 'waf_settings' );