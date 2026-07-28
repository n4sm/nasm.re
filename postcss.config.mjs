import postcssImport from 'postcss-import';
import postcssNesting from 'tailwindcss/nesting/index.js';
import tailwindcss from 'tailwindcss';

export default {
    plugins: [
        postcssImport(),          // to combine multiple css files
        postcssNesting(),
        tailwindcss(),
    ],
};
