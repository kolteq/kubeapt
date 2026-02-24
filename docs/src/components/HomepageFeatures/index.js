import React from 'react';
import clsx from 'clsx';
import styles from './styles.module.css';

const FeatureList = [
  {
    title: 'Compliance Benefits',
    Svg: require('@site/static/img/compliance.svg').default,
    description: (
      <>
      Improve compliance by enforcing consistent admission policies across clusters and producing audit-friendly validation results.
      </>
    ),
  },
  {
    title: 'Ready to use Policies and Bundles',
    Svg: require('@site/static/img/resources.svg').default,
    description: (
      <>
        Use production‑ready ValidatingAdmissionPolicy policies or bundles to secure all your Kubernetes clusters.
      </>
    ),
  },
  {
    title: 'Open Source',
    Svg: require('@site/static/img/configure.svg').default,
    description: (
      <>
        Built in Go and open sourced under the Apache 2.0 license, Kubeapt offers an optional enterprise support tier through KolTEQ.
      </>
    ),
  },
];

function Feature({Svg, title, description}) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div>
      <div className="text--center padding-horiz--md">
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
