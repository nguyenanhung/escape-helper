<?php
/**
 * CodeIgniter
 *
 * An open source application development framework for PHP
 *
 * This content is released under the MIT License (MIT)
 *
 * Copyright (c) 2014 - 2018, British Columbia Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @package      CodeIgniter
 * @author       EllisLab Dev Team
 * @copyright    Copyright (c) 2008 - 2014, EllisLab, Inc. (https://ellislab.com/)
 * @copyright    Copyright (c) 2014 - 2018, British Columbia Institute of Technology (http://bcit.ca/)
 * @license      http://opensource.org/licenses/MIT	MIT License
 * @link         https://codeigniter.com
 * @since        Version 1.0.0
 * @filesource
 */

/**
 * CodeIgniter Security Helpers
 *
 * @package        CodeIgniter
 * @subpackage     Helpers
 * @category       Helpers
 * @author         EllisLab Dev Team
 * @link           https://codeigniter.com/user_guide/helpers/security_helper.html
 */

use nguyenanhung\Libraries\Escape\Escape;

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
     * @param string
     *
     * @return    string
     */
    function encode_php_tags($str)
    {
        return (new Escape())->encodePhpTags($str);
    }
}
if (!function_exists('strip_image_tags')) {
    /**
     * Strip Image Tags
     *
     * @param string
     *
     * @return    string
     */
    function strip_image_tags($str)
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