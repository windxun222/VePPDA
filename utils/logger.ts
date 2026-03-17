/**
 * 
 * Logging Formatting Module
 *
 * This file encapsulates beautiful, structured console output functions,
 * providing a semantic logging interface to enhance test process observability 
 * and readability. All methods use ANSI color codes for styled output.
 * 
 */

export const logger = {
  /**
   * ANSI color code definitions
   */
  colors: {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    dim: '\x1b[2m',
    underline: '\x1b[4m',
    inverse: '\x1b[7m',
    hidden: '\x1b[8m',
    black: '\x1b[30m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    white: '\x1b[37m',
    bgBlack: '\x1b[40m',
    bgRed: '\x1b[41m',
    bgGreen: '\x1b[42m',
    bgYellow: '\x1b[43m',
    bgBlue: '\x1b[44m',
    bgMagenta: '\x1b[45m',
    bgCyan: '\x1b[46m',
    bgWhite: '\x1b[47m'
  },

  /**
   * Output phase title, indicating the current logical stage
   * @param {string} title - Phase name
   */
  stage(title: string) {
    console.log('');
    console.log(`${this.colors.bgBlue}${this.colors.white}${this.colors.bright} STAGE ${this.colors.reset} ${title}`);
  },

  /**
   * Output action log, indicating that a participant performed a specific operation
   * @param {string} actor - Action initiator (e.g., "Bidder A")
   * @param {string} action - Description of the action performed
   * @param {string|object} [details] - Optional details, can be a string or object
   */
  action(actor: string, action: string, details: string | undefined) {
    const actorStr = `${this.colors.cyan}${actor}${this.colors.reset}`;
    const actionStr = `${this.colors.dim}${action}${this.colors.reset}`;
    console.log(`  ${actorStr} ${actionStr}`);

    if (details) {
      const detailStr = typeof details === 'object'
        ? JSON.stringify(details, null, 2)
        : String(details);
      console.log(`${this.colors.dim}    ${detailStr}${this.colors.reset}`);
    }
  },

  /**
   * Output success message
   * @param {string} message - Success prompt text
   */
  success(message: string) {
    console.log(`${this.colors.bgGreen}${this.colors.black} SUCCESS ${this.colors.reset} ${message}`);
  },

  /**
   * Output general info message
   * @param {string} message - Info text
   */
  info(message: string) {
    console.log(`${this.colors.blue}-${this.colors.reset} ${message}`);
  },

  /**
   * Output error message
   * @param {string} message - Error description text
   */
  error(message: string) {
    console.error(`${this.colors.bgRed}${this.colors.white} ERROR ${this.colors.reset} ${message}`);
  },

  /**
   * Output separator line to distinguish different logical blocks
   */
  separator() {
    console.log(`${this.colors.dim}────────────────────────────────────────${this.colors.reset}`);
  }
};