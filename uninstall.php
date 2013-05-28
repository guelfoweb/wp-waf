<?php
/*
 * WP WAF Uninstall
 *
 * @since 1.0
 */

// Check for the 'WP_UNINSTALL_PLUGIN' constant, before executing
if ( ! defined( 'ABSPATH' ) && ! defined( 'WP_UNINSTALL_PLUGIN' ) )
	exit();

$htaccess = '../.htaccess';
$htaback  = '../original.htaccess';

if ( file_exists( $htaccess ) ) {
	if ( file_exists( $htaback ) ) {
		/* remove original .htaccess */
		unlink( $htaccess );
		/* replace .htaccess with original.htaccess */
		copy( $htaback, $htaccess );
		unlink( $htaback );
	}
}

// Delete options from the database
delete_option( 'waf_settings' );

?>
