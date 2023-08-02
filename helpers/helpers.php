<?php
/**
 * Project escape-helper
 * Created by PhpStorm
 * User: 713uk13m <dev@nguyenanhung.com>
 * Copyright: 713uk13m <dev@nguyenanhung.com>
 * Date: 09/20/2021
 * Time: 23:57
 */

use nguyenanhung\Libraries\Escape\Escape;

if (!function_exists('is_php')) {
    /**
     * Determines if the current version of PHP is equal to or greater than the supplied value
     *
     * @param string $version
     *
     * @return    bool    TRUE if the current version is $version or higher
     */
    function is_php($version)
    {
        static $_is_php;
        $version = (string) $version;

        if (!isset($_is_php[$version])) {
            $_is_php[$version] = version_compare(PHP_VERSION, $version, '>=');
        }

        return $_is_php[$version];
    }
}
if (!function_exists('escapeHtml')) {
    /**
     * Function escapeHtml
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 2018-12-09 14:24
     *
     * @param mixed $string
     *
     * @return string
     */
    function escapeHtml($string)
    {
        if ($string === null) {
            return null;
        }

        return (new Escape())->escapeHtml($string);
    }
}
if (!function_exists('htmlEscape')) {
    /**
     * Function htmlEscape
     *
     * @param mixed $string
     *
     * @return string
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 09/21/2021 00:05
     */
    function htmlEscape($string)
    {
        if ($string === null) {
            return null;
        }

        return (new Escape())->escapeHtml($string);
    }
}
if (!function_exists('escapeHtmlAttr')) {
    /**
     * Function escapeHtmlAttr
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 2018-12-09 14:24
     *
     * @param mixed $string
     *
     * @return string
     */
    function escapeHtmlAttr($string)
    {
        if ($string === null) {
            return null;
        }

        return (new Escape())->escapeHtmlAttribute($string);
    }
}
if (!function_exists('escapeHtmlAttribute')) {
    /**
     * Function escapeHtmlAttribute
     *
     * @param mixed $string
     *
     * @return string
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 09/23/2021 44:34
     */
    function escapeHtmlAttribute($string)
    {
        if ($string === null) {
            return null;
        }

        return (new Escape())->escapeHtmlAttribute($string);
    }
}
if (!function_exists('escapeJs')) {
    /**
     * Function escapeJs
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 2018-12-09 14:25
     *
     * @param mixed $string
     *
     * @return string
     */
    function escapeJs($string)
    {
        if ($string === null) {
            return null;
        }

        return (new Escape())->escapeJs($string);
    }
}
if (!function_exists('escapeInputVar')) {
    /**
     * Function escapeInputVar
     *
     * @param $var
     *
     * @return mixed|string|null
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 12/02/2023 43:13
     */
    function escapeInputVar($var)
    {
        if ($var === null) {
            return null;
        }

        return (new Escape())->escapeInput($var);
    }
}
if (!function_exists('escape_input_var')) {
    /**
     * Function escape_input_var
     *
     * @param $var
     *
     * @return mixed|string|null
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 12/02/2023 43:15
     */
    function escape_input_var($var)
    {
        return escapeInputVar($var);
    }
}
if (!function_exists('escapeCss')) {
    /**
     * Function escapeCss
     *
     * @param mixed $string
     *
     * @return string
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 09/20/2021 58:14
     */
    function escapeCss($string)
    {
        if ($string === null) {
            return null;
        }

        return (new Escape())->escapeCss($string);
    }
}
if (!function_exists('escapeUrl')) {
    /**
     * Function escapeUrl
     *
     * @author: 713uk13m <dev@nguyenanhung.com>
     * @time  : 2018-12-09 14:25
     *
     * @param mixed $string
     *
     * @return string
     */
    function escapeUrl($string)
    {
        if ($string === null) {
            return null;
        }

        return (new Escape())->escapeUrl($string);
    }
}
if (!function_exists('removeInvisibleCharacters')) {
    /**
     * Remove Invisible Characters
     *
     * This prevents sandwiching null characters
     * between ascii characters, like Java\0script.
     *
     * @param mixed $str
     * @param bool  $urlEncoded
     *
     * @return    string
     */
    function removeInvisibleCharacters($str, $urlEncoded = true)
    {
        return (new Escape())->removeInvisibleCharacters($str, $urlEncoded);
    }
}
if (!function_exists('escape_html')) {
    /**
     * Function escape_html
     *
     * @param $string
     *
     * @return string
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 05/25/2021 58:03
     */
    function escape_html($string)
    {
        return (new Escape())->escapeHtml($string);
    }
}
if (!function_exists('escape_html_attribute')) {
    /**
     * Function escape_html_attribute
     *
     * @param $string
     *
     * @return string
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 05/25/2021 58:41
     */
    function escape_html_attribute($string)
    {
        return (new Escape())->escapeHtmlAttribute($string);
    }
}
if (!function_exists('escape_js')) {
    /**
     * Function escape_js
     *
     * @param $string
     *
     * @return string
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 05/25/2021 59:04
     */
    function escape_js($string)
    {
        return (new Escape())->escapeJs($string);
    }
}
if (!function_exists('escape_css')) {
    /**
     * Function escape_css
     *
     * @param $string
     *
     * @return string
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 05/25/2021 59:24
     */
    function escape_css($string)
    {
        return (new Escape())->escapeCss($string);
    }
}
if (!function_exists('escape_url')) {
    /**
     * Function escape_url
     *
     * @param $string
     *
     * @return string
     * @author   : 713uk13m <dev@nguyenanhung.com>
     * @copyright: 713uk13m <dev@nguyenanhung.com>
     * @time     : 05/25/2021 59:40
     */
    function escape_url($string)
    {
        return (new Escape())->escapeUrl($string);
    }
}
if (!function_exists('remove_invisible_characters')) {
    /**
     * Remove Invisible Characters
     *
     * This prevents sandwiching null characters
     * between ascii characters, like Java\0script.
     *
     * @param mixed $str
     * @param bool  $urlEncoded
     *
     * @return    string
     */
    function remove_invisible_characters($str, $urlEncoded = true)
    {
        return (new Escape())->removeInvisibleCharacters($str, $urlEncoded);
    }
}
if (!function_exists('_xss_clean_')) {
    /**
     * XSS Clean
     *
     * Sanitizes data so that Cross Site Scripting Hacks can be
     * prevented.  This method does a fair amount of work but
     * it is extremely thorough, designed to prevent even the
     * most obscure XSS attempts.  Nothing is ever 100% foolproof,
     * of course, but I haven't been able to get anything passed
     * the filter.
     *
     * Note: Should only be used to deal with data upon submission.
     *     It's not something that should be used for general
     *     runtime processing.
     *
     * @link    http://channel.bitflux.ch/wiki/XSS_Prevention
     *        Based in part on some code and ideas from Bitflux.
     *
     * @link    http://ha.ckers.org/xss.html
     *        To help develop this script I used this great list of
     *        vulnerabilities along with a few other hacks I've
     *        harvested from examining vulnerabilities in other programs.
     *
     * @param string|string[] $str     Input data
     * @param bool            $isImage Whether the input is an image
     *
     * @return    array|bool|string|string[]|null
     */
    function _xss_clean_($str, $isImage = false)
    {
        return (new Escape())->xssClean($str, $isImage);
    }
}
if (!function_exists('do_hash')) {
    /**
     * Hash encode a string
     *
     * @todo          Remove in version 3.1+.
     * @deprecated    3.0.0    Use PHP's native hash() instead.
     *
     * @param string $str
     * @param string $type = 'sha1'
     *
     * @return    string
     */
    function do_hash($str, $type = 'sha1')
    {
        return (new Escape())->doHash($str, $type);
    }
}
if (!function_exists('encode_php_tags')) {
    /**
     * Convert PHP tags to entities
     *
     * @param mixed $str
     *
     * @return    string
     */
    function encode_php_tags($str)
    {
        return (new Escape())->encodePhpTags($str);
    }
}
if (!function_exists('encodePhpTags')) {
    /**
     * Convert PHP tags to entities
     *
     * @param mixed $str
     *
     * @return    string
     */
    function encodePhpTags($str)
    {
        return (new Escape())->encodePhpTags($str);
    }
}
if (!function_exists('strip_image_tags')) {
    /**
     * Strip Image Tags
     *
     * @param mixed $str
     *
     * @return    string
     */
    function strip_image_tags($str)
    {
        return (new Escape())->stripImageTags($str);
    }
}
if (!function_exists('stripImageTags')) {
    /**
     * Strip Image Tags
     *
     * @param mixed $str
     *
     * @return    string
     */
    function stripImageTags($str)
    {
        return (new Escape())->stripImageTags($str);
    }
}
if (!function_exists('sanitize_filename')) {
    /**
     * Sanitize Filename
     *
     * @param string $str           Input file name
     * @param bool   $relative_path Whether to preserve paths
     *
     * @return    string
     */
    function sanitize_filename($str, $relative_path = false)
    {
        return (new Escape())->sanitizeFilename($str, $relative_path);
    }
}
if (!function_exists('sanitizeFilename')) {
    /**
     * Sanitize Filename
     *
     * @param string $str           Input file name
     * @param bool   $relative_path Whether to preserve paths
     *
     * @return    string
     */
    function sanitizeFilename($str, $relative_path = false)
    {
        return (new Escape())->sanitizeFilename($str, $relative_path);
    }
}
if (!function_exists('bear_framework_basic_clean_str')) {
    function bear_framework_basic_clean_str($str = '')
    {
        $str = trim($str);
        $str = strip_tags($str);
        $str = htmlspecialchars($str, ENT_QUOTES | ENT_HTML5 | ENT_XHTML, 'UTF-8');

        return trim($str);
    }
}
