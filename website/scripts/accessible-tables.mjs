import { visit } from 'unist-util-visit';
import { toString } from 'mdast-util-to-string';

// Wide reference tables must remain keyboard-scrollable, including in Safari.
export default function accessibleTables() {
  return (tree) => {
    let heading = 'Reference';
    visit(tree, 'element', (node) => {
      if (/^h[1-6]$/.test(node.tagName)) heading = toString(node);
      if (node.tagName === 'table') {
        node.properties ??= {};
        node.properties.tabIndex = 0;
        node.properties.ariaLabel = `${heading} table`;
      }
    });
  };
}
